[![Build Status](https://travis-ci.org/wisespace-io/honeypot-blacklist.png?branch=master)](https://travis-ci.org/wisespace-io/honeypot-blacklist)
[![](https://meritbadge.herokuapp.com/honeypot-blacklist)](https://crates.io/crates/honeypot-blacklist)

# honeypot-blacklist
Rust library for querying Project Honeypot Blacklist ([Http:BL](http://www.projecthoneypot.org/httpbl_api.php))

# Usage

Available on crates.io

Add this to your Cargo.toml

```toml
[dependencies]
honeypot_blacklist = "0.1"
```

# Example

Simulate different Types.

```rust
extern crate honeypot_blacklist;

use honeypot_blacklist::{HoneypotBlacklist, Visitor, VisitorClass};

fn main() {
    let key = "YOUR_KEY";
    let bl = HoneypotBlacklist::new(key.into());

    let search_engine_altavista = bl.lookup("127.1.1.0".into()).unwrap();
    print_result(search_engine_altavista);

    let suspicious = bl.lookup("127.1.1.1".into()).unwrap();
    print_result(suspicious);

    let harvester = bl.lookup("127.1.1.2".into()).unwrap();
    print_result(harvester);

    let comment_spammer = bl.lookup("127.1.1.3".into()).unwrap();
    print_result(comment_spammer);
}

fn print_result(visitor: Visitor) {
    match visitor.class {
        VisitorClass::SearchEngine { name } => println!("It is just a search engine: {}", name),
        VisitorClass::Suspicious => println!("It may be a malicous Robot, not confirmed yet"),
        VisitorClass::Harvester => println!("Harvester IP"),
        VisitorClass::CommentSpammer => println!("Comment Spammer IP"),
        _ => println!("Not found"),
    }
}
```
