
use dbus::{blocking::Connection, Message, MessageItem, Path};
use std::time::Duration;

const INTROSPECTION_XML_TEMPLATE: &str = r#"<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="{path}">
  <interface name="org.freedesktop.DBus.Introspectable">
    <method name="Introspect">
      <arg name="data" direction="out" type="s"/>
    </method>
  </interface>
  <interface name="{interface}">
    <method name="ClearCache"/>
    <method name="GetVersion">
      <arg name="version" direction="out" type="s"/>
    </method>
    <method name="SetServers">
      <arg name="servers" direction="in" type="av"/>
    </method>
    <method name="SetDomainServers">
      <arg name="servers" direction="in" type="as"/>
    </method>
    <method name="SetServersEx">
      <arg name="servers" direction="in" type="aas"/>
    </method>
    <method name="SetFilterWin2KOption">
      <arg name="filterwin2k" direction="in" type="b"/>
    </method>
    <method name="SetFilterA">
      <arg name="filter-a" direction="in" type="b"/>
    </method>
    <method name="SetFilterAAAA">
      <arg name="filter-aaaa" direction="in" type="b"/>
    </method>
    <method name="SetLocaliseQueriesOption">
      <arg name="localise-queries" direction="in" type="b"/>
    </method>
    <method name="SetBogusPrivOption">
      <arg name="boguspriv" direction="in" type="b"/>
    </method>
    <signal name="DhcpLeaseAdded">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>
    <signal name="DhcpLeaseDeleted">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>
    <signal name="DhcpLeaseUpdated">
      <arg name="ipaddr" type="s"/>
      <arg name="hwaddr" type="s"/>
      <arg name="hostname" type="s"/>
    </signal>
    <method name="GetMetrics">
      <arg name="metrics" direction="out" type="a{su}"/>
    </method>
    <method name="GetServerMetrics">
      <arg name="metrics" direction="out" type="a{ss}"/>
    </method>
    <method name="ClearMetrics"/>
  </interface>
</node>"#;

struct Watch {
    watch: dbus::Watch,
    next: Option<Box<Watch>>,
}

impl Watch {
    fn new(watch: dbus::Watch) -> Self {
        Watch { watch, next: None }
    }
}

struct Daemon {
    watches: Option<Box<Watch>>,
    dbus_name: String,
    query_port: u16,
    addr_buff: String,
    name_buff: String,
    metrics: Vec<u32>,
    servers: Vec<Server>,
}

struct Server {
    addr: String,
    flags: u32,
    queries: u32,
    failed_queries: u32,
    nxdomain_replies: u32,
    retrys: u32,
    query_latency: u32,
    next: Option<Box<Server>>,
}

impl Daemon {
    fn new(dbus_name: String, query_port: u16) -> Self {
        Daemon {
            watches: None,
            dbus_name,
            query_port,
            addr_buff: String::new(),
            name_buff: String::new(),
            metrics: vec![0; __METRIC_MAX],
            servers: Vec::new(),
        }
    }
}

fn add_watch(watch: dbus::Watch, data: &mut Daemon) -> bool {
    let mut w = &mut data.watches;
    while let Some(ref mut current) = w {
        if current.watch == watch {
            return true;
        }
        w = &mut current.next;
    }

    let new_watch = Box::new(Watch::new(watch));
    new_watch.next = data.watches.take();
    data.watches = Some(new_watch);
    true
}

fn remove_watch(watch: dbus::Watch, data: &mut Daemon) {
    let mut w = &mut data.watches;
    while let Some(ref mut current) = w {
        if current.watch == watch {
            *w = current.next.take();
            return;
        }
        w = &mut current.next;
    }
}

fn dbus_read_servers(message: &Message) -> Result<(), String> {
    let iter = message.iter_init().ok_or("Failed to initialize dbus message iter")?;
    // ...existing code...
    Ok(())
}

fn dbus_set_bool(message: &Message, flag: u32, name: &str) -> Result<(), String> {
    let iter = message.iter_init().ok_or("Expected boolean argument")?;
    let enabled: bool = iter.read().map_err(|_| "Expected boolean argument")?;
    if enabled {
        println!("Enabling --{} option from D-Bus", name);
        // set_option_bool(flag);
    } else {
        println!("Disabling --{} option from D-Bus", name);
        // reset_option_bool(flag);
    }
    Ok(())
}

fn message_handler(connection: &Connection, message: &Message, data: &mut Daemon) -> Result<(), String> {
    let method = message.member().ok_or("No method name")?;
    let mut clear_cache = false;
    let mut new_servers = false;

    match method.as_str() {
        "Introspect" => {
            let introspection_xml = INTROSPECTION_XML_TEMPLATE.replace("{path}", DNSMASQ_PATH).replace("{interface}", &data.dbus_name);
            let reply = Message::new_method_return(message).append1(introspection_xml);
            connection.send(reply).map_err(|_| "Failed to send reply")?;
        }
        "GetVersion" => {
            let version = VERSION;
            let reply = Message::new_method_return(message).append1(version);
            connection.send(reply).map_err(|_| "Failed to send reply")?;
        }
        "SetServers" => {
            dbus_read_servers(message)?;
            new_servers = true;
        }
        "SetFilterWin2KOption" => {
            dbus_set_bool(message, OPT_FILTER, "filterwin2k")?;
        }
        "SetFilterA" => {
            // ...existing code...
        }
        "SetFilterAAAA" => {
            // ...existing code...
        }
        "SetLocaliseQueriesOption" => {
            dbus_set_bool(message, OPT_LOCALISE, "localise-queries")?;
        }
        "SetBogusPrivOption" => {
            dbus_set_bool(message, OPT_BOGUSPRIV, "bogus-priv")?;
        }
        "ClearCache" => clear_cache = true,
        _ => return Err("Method not handled".to_string()),
    }

    if new_servers {
        println!("setting upstream servers from DBus");
        // check_servers(0);
        if option_bool(OPT_RELOAD) {
            clear_cache = true;
        }
    }

    if clear_cache {
        // clear_cache_and_reload(dnsmasq_time());
    }

    Ok(())
}

fn dbus_init(dbus_name: &str) -> Result<Connection, String> {
    let connection = Connection::new_system().map_err(|_| "Failed to connect to D-Bus")?;
    connection.request_name(dbus_name, false, true, false).map_err(|_| "Failed to request name")?;
    connection.register_object_path(DNSMASQ_PATH, move |conn, msg| {
        let mut data = Daemon::new(dbus_name.to_string(), 0);
        message_handler(conn, msg, &mut data).unwrap_or_else(|e| println!("Error handling message: {}", e));
        true
    }).map_err(|_| "Failed to register object path")?;
    Ok(connection)
}

fn main() {
    let dbus_name = "com.example.Dnsmasq";
    let connection = dbus_init(dbus_name).expect("Failed to initialize D-Bus");
    loop {
        connection.process(Duration::from_millis(1000)).expect("Failed to process D-Bus messages");
    }
}