//! # honeypot_blacklist
//! [Http:BL API Specification](http://www.projecthoneypot.org/httpbl_api.php)
#![deny(warnings)]

extern crate domain;
extern crate futures;
extern crate tokio_core;

use std::fmt;
use std::error;
use std::str::FromStr;
use domain::bits::DNameBuf;
use domain::resolv::Resolver;
use domain::resolv::lookup::lookup_host;
use tokio_core::reactor::Core;
use domain::resolv::error::Error as domainError;

static HTTPBL_HOST : &'static str = "dnsbl.httpbl.org";

#[derive(Debug, Clone, PartialEq)]
pub enum VisitorClass {
    SearchEngine{name: String},
    Suspicious,
    Harvester,
    CommentSpammer,
    SuspiciousHarvester,
    SuspiciousCommentSpammer,
    SuspiciousHarvesterCommentSpammer,
    NotClassified,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Rating {
    NotClassified,
    Low,
    Medium,
    High,
    Dangerous
}

#[derive(Debug)]
pub struct Visitor {
    pub class: VisitorClass,
    pub threat_rating: Rating,
    pub last_activity: u16,
}

#[derive(Debug)]
pub enum HoneypotBlacklistError {
    InvalidApiKey,
    Domain(domainError),
}

impl fmt::Display for HoneypotBlacklistError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HoneypotBlacklistError::Domain(ref err) => write!(f, "DNS error: {}", err),
            HoneypotBlacklistError::InvalidApiKey => write!(f, "Invalid Api Key"),
        }
    }
}

impl error::Error for HoneypotBlacklistError {
    fn description(&self) -> &str {
        match *self {
            HoneypotBlacklistError::Domain(ref err) => err.description(),
            HoneypotBlacklistError::InvalidApiKey => "Invalid Api Key",
        }
    }
}

impl From<domainError> for HoneypotBlacklistError {
    fn from(err: domainError) -> HoneypotBlacklistError {
        HoneypotBlacklistError::Domain(err)
    }
}

pub struct HoneypotBlacklist {
    key: String,
}

impl HoneypotBlacklist {
    /// Creates a new HoneypotBlacklist instance.
    ///
    /// * `key` - The API Key.
    pub fn new(key: String) -> HoneypotBlacklist {
        HoneypotBlacklist {
            key: key,
        }
    }

    pub fn lookup(&self, ip: String) -> Result<Visitor, HoneypotBlacklistError> {
        let reversed_ip = ip.rsplit('.').collect::<Vec<&str>>().join(".");
        let query_str = format!("{}.{}.{}", self.key, reversed_ip, HTTPBL_HOST);

        let mut core = Core::new().unwrap();
        let resolv = Resolver::new(&core.handle());

        let name = DNameBuf::from_str(&query_str).unwrap();
        let addrs = lookup_host(resolv, name);

        match core.run(addrs) {
            Ok(addrs) => {
                let addr: String = format!("{}", addrs.iter().nth(0).unwrap());
                let visitor: Vec<_> = addr.split('.').collect();
                Ok(Visitor {
                    class: self.get_visitor_class(visitor[3], visitor[2]),
                    threat_rating: self.get_threat_rating(visitor[2]),
                    last_activity: self.get_last_activity(visitor[1]),
                })
            }
            Err(e) => Err(HoneypotBlacklistError::Domain(e))
        }
    }

    fn get_visitor_class(&self, class: &str, engine: &str) -> VisitorClass {
        match class {
            "0" => VisitorClass::SearchEngine { name: self.get_search_engine(engine) },
            "1" => VisitorClass::Suspicious,
            "2" => VisitorClass::Harvester,
            "3" => VisitorClass::CommentSpammer,
            "4" => VisitorClass::SuspiciousHarvester,
            "5" => VisitorClass::SuspiciousCommentSpammer,
            "6" => VisitorClass::SuspiciousHarvesterCommentSpammer,
            _ => VisitorClass::NotClassified,
        }
    }

    // Gets the threat rating for an ip address if it is listed in the httpBL.
    // Reference: http://www.projecthoneypot.org/threat_info.php
    fn get_threat_rating(&self, value: &str) -> Rating {
        let rating: u16 = value.parse().unwrap();
        match rating {
            1  ... 25 => Rating::Low,
            26 ... 50 => Rating::Medium,
            51 ... 75 => Rating::High,
            76 ... 255 => Rating::Dangerous,
            _ => Rating::NotClassified
        }
    }

    // Gets the number of days since an activity was registered for the ip address
    // This value ranges from 0 to 255 days.
    fn get_last_activity(&self, value: &str) -> u16 {
        let last_activity: u16 = value.parse().unwrap();
        last_activity
    }

    // Gets the search engine name
    fn get_search_engine(&self, engine_code: &str) -> String {
        match engine_code {
            "0" => "Undocumented".into(),
            "1" => "AltaVista".into(),
            "2" => "Ask".into(),
            "3" => "Baidu".into(),
            "4" => "Excite".into(),
            "5" => "Google".into(),
            "6" => "Looksmart".into(),
            "7" => "Lycos".into(),
            "8" => "MSN".into(),
            "9" => "Yahoo".into(),
            "10" => "Cuil".into(),
            "11" => "InfoSeek".into(),
            "12" => "Miscellaneous".into(),
            _ => "NotFound".into()
        }
    }
}