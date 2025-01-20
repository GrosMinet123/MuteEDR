//! Windows Filtering Platform (WFP) Network Traffic Control
//! 
//! This module provides functionality to control network traffic using the Windows Filtering Platform.
//! It allows for comprehensive network traffic blocking at various layers of the network stack.
//! 
//! # Safety Considerations
//! - These functions can completely block all network traffic if not used carefully
//! - Ensure physical access to the machine before testing
//! - Have a backup plan for removing filters (use unblock_process_traffic)
//! - Test in a controlled environment first


use std::path::Path;
use windows::{
    core::{GUID, HSTRING, PCWSTR, PWSTR},
    Win32::{Foundation::{ERROR_SUCCESS, HANDLE}, NetworkManagement::WindowsFilteringPlatform::{FwpmEngineClose0, FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterCreateEnumHandle0, FwpmFilterDeleteById0, FwpmFilterDestroyEnumHandle0, FwpmFilterEnum0, FwpmFreeMemory0, FwpmGetAppIdFromFileName0, FwpmProviderAdd0, FwpmProviderDeleteByKey0, FwpmProviderGetByKey0, FWPM_ACTION0, FWPM_CONDITION_ALE_APP_ID, FWPM_DISPLAY_DATA0, FWPM_FILTER0, FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERSISTENT, FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6, FWPM_PROVIDER0, FWPM_PROVIDER_FLAG_PERSISTENT, FWP_ACTION_BLOCK, FWP_BYTE_BLOB, FWP_BYTE_BLOB_TYPE, FWP_MATCH_EQUAL, FWP_UINT64, FWP_VALUE0}, System::Rpc::RPC_C_AUTHN_DEFAULT},
};


/// Provider GUID for identifying our filters
/// This unique identifier is used to track and manage our WFP filters
const PROVIDER_KEY: GUID = GUID {
    data1: 0x012504be,
    data2: 0x033a,
    data3: 0xa911,
    data4: [0x22, 0x00, 0x81, 0x19, 0x20, 0x02, 0xb2, 0xbb],
};


/// Removes all network filters associated with our provider
/// 
/// This function:
/// 1. Opens a handle to the WFP engine
/// 2. Enumerates all filters
/// 3. Removes filters matching our provider key
/// 4. Cleans up the provider
/// 
/// # Returns
/// - `Ok(())` if all operations succeed
/// - `Err(Box<dyn Error>)` if any operation fails
/// 
/// # Safety
/// This function uses unsafe Windows API calls but handles cleanup appropriately
pub fn unblock_process_traffic() -> Result<(), Box<dyn std::error::Error>> {
    // Open WFP engine
    let mut h_engine = HANDLE::default();
    unsafe {
        let result = FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            None,
            &mut h_engine,
        );
        if result != 0 {
            return Err(windows::core::Error::from_win32().into());
        }
    }

    let mut enum_handle = HANDLE::default();
    unsafe {
        let result = FwpmFilterCreateEnumHandle0(h_engine, None, &mut enum_handle);
        if result != 0 {
            return Err(windows::core::Error::from_win32().into());
        }
    }

    loop {
        let mut entries: *mut *mut FWPM_FILTER0 = std::ptr::null_mut();
        let mut num_entries_returned: u32 = 0;
        let result = unsafe { 
            FwpmFilterEnum0(
                h_engine, 
                enum_handle, 
                1,  // Request one entry at a time
                &mut entries,
                &mut num_entries_returned
            ) 
        };
        
        if result != ERROR_SUCCESS.0 {
            unsafe {
                FwpmFilterDestroyEnumHandle0(h_engine, enum_handle);
                FwpmEngineClose0(h_engine);
            }
            return Err(windows::core::Error::from_win32().into());
        }

        if num_entries_returned == 0 {
            // Free the memory allocated for entries
            unsafe {
                FwpmFreeMemory0(entries as *mut _);
            }
            break;
        }

        unsafe {
            // Get the filter entry
            let filter = *entries;
            if !filter.is_null() {
                // Check if this filter belongs to our provider
                if (*filter).providerKey != std::ptr::null_mut() && 
                   (*(*filter).providerKey) == PROVIDER_KEY {

                    // Delete the filter using its ID
                    let result = FwpmFilterDeleteById0(h_engine, (*filter).filterId);
                    match result {
                        0 => {
                            println!("Deleted filter with ID: {}", (*filter).filterId);
                        },
                        _ => {
                            println!("Failed to delete filter with ID: {}", (*filter).filterId);
                        }
                    }
                }
            }
        }
    }

    
    unsafe {
        // Remove provider, don't return error if no provider found
        FwpmProviderDeleteByKey0(h_engine, &PROVIDER_KEY);
        FwpmFilterDestroyEnumHandle0(h_engine, enum_handle);
        FwpmEngineClose0(h_engine);
    }
    
    Ok(())
}


/// Blocks network traffic using WFP filters
/// 
/// This function creates comprehensive network blocks by adding filters at multiple network layers:
/// - Outbound connections (IPv4/IPv6)
/// 
/// # Arguments
/// * `full_path` - Path to the process executable (used for app ID in some scenarios)
/// 
/// # Returns
/// - `Ok(())` if all filters are successfully added
/// - `Err(Box<dyn Error>)` if any operation fails
/// 

pub fn block_process_traffic(full_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Convert path to wide string
    let path = Path::new(full_path);
    if !path.exists() {
        return Err("File does not exist".into());
    }

    let w_full_path = HSTRING::from(full_path);
    
    // Open WFP engine
    let mut h_engine = HANDLE::default();
    unsafe {
        let result = FwpmEngineOpen0(
            None,
            RPC_C_AUTHN_DEFAULT as u32,
            None,
            None,
            &mut h_engine,
        );
        if result != 0 {
            return Err(windows::core::Error::from_win32().into());
        }
    }

    // Get app ID
    let mut app_id: *mut FWP_BYTE_BLOB = std::ptr::null_mut();
    unsafe {
        let result = FwpmGetAppIdFromFileName0(PCWSTR::from_raw(w_full_path.as_ptr()), &mut app_id);
        if result != 0 {
            FwpmEngineClose0(h_engine);
            return Err(windows::core::Error::from_win32().into());
        }
    }

    // Set up filter condition
    let mut cond = FWPM_FILTER_CONDITION0::default();
    cond.fieldKey = FWPM_CONDITION_ALE_APP_ID;
    cond.matchType = FWP_MATCH_EQUAL;
    cond.conditionValue.r#type = FWP_BYTE_BLOB_TYPE;
    cond.conditionValue.Anonymous.byteBlob = app_id;

    let mut provider_key = GUID::from(PROVIDER_KEY);
    // Set up filter
    let mut weight_value: u64 = 0xFFFFFFFFFFFFFFFF;
    let filter_name = HSTRING::from("Block Process Traffic");
    let mut filter = FWPM_FILTER0 {
        displayData: FWPM_DISPLAY_DATA0 {
            name: PWSTR::from_raw(filter_name.as_ptr() as *mut _),
            description: PWSTR::null(),
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        filterKey: GUID::zeroed(),
        layerKey: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        subLayerKey: GUID::zeroed(),
        weight: FWP_VALUE0 {
            r#type: FWP_UINT64,
            Anonymous: windows::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 {
                uint64: &mut weight_value as *mut u64,
            },
        },
        providerKey: &mut provider_key,
        numFilterConditions: 1,
        filterCondition: &mut cond,
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: Default::default(),
        },
        ..Default::default()
    };

    // Add provider
    let provider_name = HSTRING::from("CustomProvider123");
    let provider_desc = HSTRING::from("CustomProviderDescription123");

    let mut provider_handle: *mut FWPM_PROVIDER0 = std::ptr::null_mut();
    unsafe {
        
        
        // Try to get existing provider first
        match FwpmProviderGetByKey0(h_engine, &provider_key, &mut provider_handle) {
            0 => {
                println!("Provider exists");
            },
            _ => {
                // Provider doesn't exist, create new one
                let new_provider = FWPM_PROVIDER0 {
                    displayData: FWPM_DISPLAY_DATA0 {
                        name: PWSTR::from_raw(provider_name.as_ptr() as *mut _),
                        description: PWSTR::from_raw(provider_desc.as_ptr() as *mut _),
                    },
                    flags: FWPM_PROVIDER_FLAG_PERSISTENT,
                    providerKey: PROVIDER_KEY,
                    ..Default::default()
                };
                
                if FwpmProviderAdd0(h_engine, &new_provider, None) != 0 {
                    FwpmFreeMemory0(app_id as *mut _);
                    FwpmFreeMemory0(provider_handle as *mut _);
                    FwpmEngineClose0(h_engine);
                    return Err(windows::core::Error::from_win32().into());
                }
                
                println!("Provider created: key {:?}", new_provider.providerKey);
            }
        }
    };

    // Add filters for both IPv4 and IPv6
    let mut filter_id = 0;
    unsafe {
        // Add IPv4 filter
        let result = FwpmFilterAdd0(h_engine, &filter, None, Some(&mut filter_id));
        if result == 0 {
            println!("Added WFP filter for \"{}\" (Filter id: {}, IPv4 layer)", full_path, filter_id);
        } else {
            println!("Failed to add filter in IPv4 layer");
        }

        // Add IPv6 filter
        filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
        let result = FwpmFilterAdd0(h_engine, &filter, None, Some(&mut filter_id));
        if result == 0 {
            println!("Added WFP filter for \"{}\" (Filter id: {}, IPv6 layer)", full_path, filter_id);
        } else {
            println!("Failed to add filter in IPv6 layer");
        }
    }
    // Free app ID first
    unsafe {
        FwpmFreeMemory0(app_id as *mut _);
        FwpmFreeMemory0(provider_handle as *mut _);
    }
    // Then close the engine
    unsafe {
        FwpmEngineClose0(h_engine);
    }

    

    Ok(())
}


/// Main entry point for the application
/// 
/// Handles command-line arguments and executes the appropriate function:
/// - `block <path>`: Blocks network traffic
/// - `unblock`: Removes all filters
fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        println!("Usage:");
        println!("  {} block <path>", args[0]);
        println!("  {} unblock", args[0]);
        return;
    }

    let command = &args[1];
    let result = match command.as_str() {
        "block" => {
            if args.len() < 3 {
                println!("Error: 'block' command requires a path");
                println!("Usage: {} block <path>", args[0]);
                return;
            }
            block_process_traffic(&args[2])
        },
        "unblock" => unblock_process_traffic(),
        _ => {
            println!("Invalid command. Use 'block' or 'unblock'");
            return;
        }
    };

    if let Err(e) = result {
        println!("Operation failed: {:?}", e);
    } else {
        println!("Operation completed successfully");
    }
}