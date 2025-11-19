// Test to understand pnet TcpOption API
use pnet::packet::tcp::TcpOption;

fn main() {
    // Create various TCP options
    let mss = TcpOption::mss(1460);
    let wscale = TcpOption::wscale(7);
    let sack_perm = TcpOption::sack_perm();
    let nop = TcpOption::nop();
    let timestamp = TcpOption::timestamp(12345, 0);

    // Check what methods are available
    println!("MSS: {:?}", mss);
    println!("WScale: {:?}", wscale);
    println!("SACK Perm: {:?}", sack_perm);
    println!("NOP: {:?}", nop);
    println!("Timestamp: {:?}", timestamp);

    // Try to get the kind
    println!("MSS kind: {:?}", mss.get_number());
    println!("MSS length: {:?}", mss.get_length());
    println!("MSS data: {:?}", mss.get_data());
}
