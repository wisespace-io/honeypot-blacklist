extern crate honeypot_blacklist;

use honeypot_blacklist::{HoneypotBlacklist, Visitor, VisitorClass, Rating};

fn main() {
    let key = "YOUR_KEY";
    let bl = HoneypotBlacklist::new(key.into()); 

    // Simulate different Threat levels
    let low_suspicious = bl.lookup("127.1.10.1".into()).unwrap();
    print_result(low_suspicious); 

    let medium = bl.lookup("127.1.40.1".into()).unwrap();
    print_result(medium);

    let dangerous = bl.lookup("127.1.80.1".into()).unwrap();
    print_result(dangerous);
}

fn print_result(visitor: Visitor) {
    let class = visitor.class;
    match visitor.threat_rating {
        Rating::Low if class == VisitorClass::Suspicious => println!("It is probably a harmless robot"),
        Rating::Medium => println!("Medium"),
        Rating::High => println!("High"),
        Rating::Dangerous => println!("Dangerous. Last seem {} day(s) ago", visitor.last_activity),
        _ => println!("Not Classified - Score Level 0"),
    }
}
