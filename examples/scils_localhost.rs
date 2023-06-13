use std::ffi::{CString, c_void};

use rasta_sys::{
    rasta_lib_configuration_t, rasta_ip_data, rasta_lib_init_configuration, rasta_config_info, logger_t, 
    rasta_connection_config, rasta_bind, sr_listen, rasta_accept, sr_connect, sr_cleanup, load_configfile, rasta_send, rasta_recv, sr_disconnect
};
use sci_rs::SCITelegram;
use sci_rs::scils::SCILSBrightness;

const ID_R: u64 = 0x61;
const ID_S: u64 = 0x60;
const BUF_SIZE: usize = 500;

fn main() {
    let role = std::env::args().nth(1).unwrap();

    let rc = unsafe { std::mem::zeroed::<rasta_lib_configuration_t>() }.as_mut_ptr();
    let mut to_server = [unsafe { std::mem::zeroed::<rasta_ip_data>() }; 2];

    if role == "r" {
        println!("->   R (ID = 0x{:x}", ID_R);
        let cfg_path = CString::new("examples/config/rasta_server_local.cfg").unwrap();
        let mut config = unsafe { std::mem::zeroed::<rasta_config_info>() };
        let mut logger = unsafe { std::mem::zeroed::<logger_t>() };
        unsafe { load_configfile(&mut config, &mut logger, cfg_path.as_ptr()) };

        to_server[0].ip = unsafe { std::mem::transmute::<[u8; 16], [i8; 16]>(*b"127.0.0.1\0\0\0\0\0\0\0") };
        to_server[1].ip = unsafe { std::mem::transmute::<[u8; 16], [i8; 16]>(*b"127.0.0.1\0\0\0\0\0\0\0") };
        to_server[0].port = 9998;
        to_server[1].port = 9999;

        let mut connection_config = rasta_connection_config {
            config: &mut config, 
            rasta_id: ID_S, 
            transport_sockets: &mut to_server as *mut rasta_ip_data, 
            transport_sockets_count: 2
        };

        unsafe { rasta_lib_init_configuration(rc, &mut config, &mut logger, &mut connection_config, 1) };
        unsafe { rasta_bind(&mut (*rc).h)};
        unsafe { sr_listen(&mut (*rc).h)};

        let connection = unsafe { rasta_accept(rc) };

        if connection == std::ptr::null_mut() {
            println!("Could not accept connection!");
        }

        let mut received = vec![0; BUF_SIZE];
        unsafe { rasta_recv(rc, connection, received.as_mut_ptr() as *mut c_void, BUF_SIZE)};
        let telegram: SCITelegram = received.as_slice().try_into().expect("Could not convert received packet into SCITelegram");

        println!("Received Telegram: {}", telegram.message_type.try_as_scils_message_type().unwrap());
        dbg!(&telegram.sender);
        dbg!(&telegram.receiver);
        dbg!(telegram.payload.used);
        
    } else if role == "s" {
        println!("->   S (ID = 0x{:x}", ID_S);
        let cfg_path = CString::new("examples/config/rasta_client_local.cfg").unwrap();
        let mut config = unsafe { std::mem::zeroed::<rasta_config_info>() };
        let mut logger = unsafe { std::mem::zeroed::<logger_t>() };
        unsafe { load_configfile(&mut config, &mut logger, cfg_path.as_ptr()) };

        to_server[0].ip = unsafe { std::mem::transmute::<[u8; 16], [i8; 16]>(*b"127.0.0.1\0\0\0\0\0\0\0") };
        to_server[1].ip = unsafe { std::mem::transmute::<[u8; 16], [i8; 16]>(*b"127.0.0.1\0\0\0\0\0\0\0") };
        to_server[0].port = 8888;
        to_server[1].port = 8889;

        let mut connection_config = rasta_connection_config {
            config: &mut config, 
            rasta_id: ID_R, 
            transport_sockets: &mut to_server as *mut rasta_ip_data, 
            transport_sockets_count: 2
        };

        unsafe { rasta_lib_init_configuration(rc, &mut config, &mut logger, &mut connection_config, 1) };
        unsafe { rasta_bind(&mut (*rc).h)};
        let connection = unsafe { sr_connect(&mut (*rc).h, ID_R)};

        if connection == std::ptr::null_mut() {
            println!("Failed to connect any channel!");
        }

        let mut telegram_as_vec: Vec<u8> = SCITelegram::scils_change_brightness("S", "R", SCILSBrightness::Night).into();
        let buf = telegram_as_vec.as_mut_ptr() as *mut c_void;
        unsafe { rasta_send(rc, connection, buf, telegram_as_vec.len()) };
        println!("Sent change brightness telegram!");
        unsafe { sr_disconnect(connection) };
    }

    unsafe { sr_cleanup(&mut (*rc).h) };
}
