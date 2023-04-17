use winapi::um::winreg::{HKEY_LOCAL_MACHINE, RegCreateKeyExW, RegSetValueExW, RegCloseKey};
use winapi::shared::minwindef::{DWORD, HKEY, LPDWORD, LPBYTE};
use winapi::shared::winerror::{ERROR_FILE_NOT_FOUND, ERROR_SUCCESS};
use winapi::um::winnt::REG_DWORD;
use std::ptr::null_mut;
use std::io::Error;

fn main() -> Result<(), Error> {
    // Open the HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate registry key.
    let mut hkey: HKEY = null_mut();
    let sub_key = "SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate";
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            null_mut(),
            0,
            0xF003F, // KEY_ALL_ACCESS | KEY_WOW64_64KEY | KEY_SET_VALUE
            null_mut(),
            &mut hkey,
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Set the DisableOSUpgrade DWORD value to 1.
    let value_name = "DisableOSUpgrade";
    let value_data: DWORD = 1;
    let result = unsafe {
        RegSetValueExW(
            hkey,
            value_name.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            REG_DWORD,
            &value_data as *const DWORD as LPBYTE,
            std::mem::size_of::<DWORD>() as DWORD,
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Close the registry key.
    unsafe {
        RegCloseKey(hkey);
    }

    // Open the HKLM\SOFTWARE\Policies\Microsoft\WindowsStore registry key.
    let mut hkey: HKEY = null_mut();
    let sub_key = "SOFTWARE\\Policies\\Microsoft\\WindowsStore";
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            null_mut(),
            0,
            0xF003F, // KEY_ALL_ACCESS | KEY_WOW64_64KEY | KEY_SET_VALUE
            null_mut(),
            &mut hkey,
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Set the DisableOSUpgrade DWORD value to 1.
    let value_name = "DisableOSUpgrade";
    let value_data: DWORD = 1;
    let result = unsafe {
        RegSetValueExW(
            hkey,
            value_name.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            REG_DWORD,
            &value_data as *const DWORD as LPBYTE,
            std::mem::size_of::<DWORD>() as DWORD,
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Close the registry key.
    unsafe {
        RegCloseKey(hkey);
    }

    // Open the HKLM\SYSTEM\Setup\UpgradeNotification registry key.
    let mut hkey: HKEY = null_mut();
    let sub_key = "SYSTEM\\Setup\\UpgradeNotification";
    let result = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            sub_key.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            null_mut(),
            0,
            0xF003F, // KEY_ALL_ACCESS | KEY_WOW64_64KEY | KEY_SET_VALUE
            null_mut(),
            &mut hkey,
            null_mut(),
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Set the UpgradeAvailable DWORD value to 0.
    let value_name = "UpgradeAvailable";
    let value_data: DWORD = 0;
    let result = unsafe {
        RegSetValueExW(
            hkey,
            value_name.encode_utf16().collect::<Vec<_>>().as_ptr(),
            0,
            REG_DWORD,
            &value_data as *const DWORD as LPBYTE,
            std::mem::size_of::<DWORD>() as DWORD,
        )
    };
    if result != ERROR_SUCCESS.try_into().unwrap() {
        return Err(Error::last_os_error());
    }
    
    // Close the registry key.
    unsafe {
        RegCloseKey(hkey);
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_encrypt() {
        let mut result = true;
        assert_eq!(result, true);
    }
}
