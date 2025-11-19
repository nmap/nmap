use crate::signatures::{ServiceSignature, VersionInfo};

/// Tier 3 IoT & Industrial Protocols - IoT messaging and industrial control system signatures
/// Covers MQTT variants, Modbus, CoAP, BACnet, OPC UA, AMQP, DDS, and industrial automation protocols
pub fn load_tier3_iot_signatures() -> Vec<ServiceSignature> {
    let mut signatures = Vec::new();

    // ========== MQTT & MQTT-SN ==========

    // MQTT v3.1.1
    signatures.push(ServiceSignature {
        service_name: "mqtt".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"\x10.*MQTT/3\.1\.1".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MQTT".to_string()),
            version: Some("3.1.1".to_string()),
            info: Some("IoT messaging protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:mqtt:mqtt:3.1.1".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // MQTT v5.0
    signatures.push(ServiceSignature {
        service_name: "mqtt5".to_string(),
        probe_name: "MQTT".to_string(),
        pattern: r"\x10.*MQTT/5\.0".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MQTT".to_string()),
            version: Some("5.0".to_string()),
            info: Some("Enhanced IoT protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:mqtt:mqtt:5.0".to_string()],
        }),
        ports: vec![1883, 8883],
        protocol: "tcp".to_string(),
    });

    // MQTT over WebSocket
    signatures.push(ServiceSignature {
        service_name: "mqtt-ws".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Upgrade: websocket.*mqtt".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MQTT over WebSocket".to_string()),
            version: None,
            info: Some("Browser-compatible MQTT".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:mqtt:mqtt".to_string()],
        }),
        ports: vec![8083, 8084, 9001],
        protocol: "tcp".to_string(),
    });

    // MQTT-SN (MQTT for Sensor Networks)
    signatures.push(ServiceSignature {
        service_name: "mqtt-sn".to_string(),
        probe_name: "MQTTSN".to_string(),
        pattern: r"MQTT-SN".to_string(),
        version_info: Some(VersionInfo {
            product: Some("MQTT-SN".to_string()),
            version: None,
            info: Some("MQTT for sensor networks".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:mqtt:mqtt_sn".to_string()],
        }),
        ports: vec![1883],
        protocol: "udp".to_string(),
    });

    // ========== CoAP (CONSTRAINED APPLICATION PROTOCOL) ==========

    // CoAP
    signatures.push(ServiceSignature {
        service_name: "coap".to_string(),
        probe_name: "CoAP".to_string(),
        pattern: r"[\x40-\x7f][\x00-\xff]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("CoAP".to_string()),
            version: None,
            info: Some("Constrained Application Protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:ietf:coap".to_string()],
        }),
        ports: vec![5683],
        protocol: "udp".to_string(),
    });

    // CoAP over DTLS
    signatures.push(ServiceSignature {
        service_name: "coaps".to_string(),
        probe_name: "CoAPS".to_string(),
        pattern: r"[\x16-\x17][\x03]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("CoAP over DTLS".to_string()),
            version: None,
            info: Some("Secure CoAP".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:ietf:coap".to_string()],
        }),
        ports: vec![5684],
        protocol: "udp".to_string(),
    });

    // CoAP over TCP
    signatures.push(ServiceSignature {
        service_name: "coap-tcp".to_string(),
        probe_name: "CoAP".to_string(),
        pattern: r"coap\+tcp".to_string(),
        version_info: Some(VersionInfo {
            product: Some("CoAP over TCP".to_string()),
            version: None,
            info: Some("TCP-based CoAP".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:ietf:coap".to_string()],
        }),
        ports: vec![5683],
        protocol: "tcp".to_string(),
    });

    // ========== MODBUS ==========

    // Modbus TCP
    signatures.push(ServiceSignature {
        service_name: "modbus-tcp".to_string(),
        probe_name: "Modbus".to_string(),
        pattern: r"^\x00[\x00-\xff]\x00\x00\x00[\x06-\xff]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Modbus TCP".to_string()),
            version: None,
            info: Some("Industrial automation protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:modbus:modbus_tcp".to_string()],
        }),
        ports: vec![502],
        protocol: "tcp".to_string(),
    });

    // Modbus RTU over TCP
    signatures.push(ServiceSignature {
        service_name: "modbus-rtu-tcp".to_string(),
        probe_name: "Modbus".to_string(),
        pattern: r"modbus.*rtu".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Modbus RTU over TCP".to_string()),
            version: None,
            info: Some("Serial Modbus tunneled over TCP".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:modbus:modbus_rtu".to_string()],
        }),
        ports: vec![502],
        protocol: "tcp".to_string(),
    });

    // Modbus Gateway
    signatures.push(ServiceSignature {
        service_name: "modbus-gateway".to_string(),
        probe_name: "Modbus".to_string(),
        pattern: r"modbus.*gateway".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Modbus Gateway".to_string()),
            version: None,
            info: Some("Protocol converter".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:modbus:modbus_gateway".to_string()],
        }),
        ports: vec![502],
        protocol: "tcp".to_string(),
    });

    // ========== BACNET ==========

    // BACnet/IP
    signatures.push(ServiceSignature {
        service_name: "bacnet".to_string(),
        probe_name: "BACnet".to_string(),
        pattern: r"\x81".to_string(),
        version_info: Some(VersionInfo {
            product: Some("BACnet/IP".to_string()),
            version: None,
            info: Some("Building automation protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("building-control".to_string()),
            cpe: vec!["cpe:/a:bacnet:bacnet".to_string()],
        }),
        ports: vec![47808],
        protocol: "udp".to_string(),
    });

    // BACnet Secure Connect
    signatures.push(ServiceSignature {
        service_name: "bacnet-sc".to_string(),
        probe_name: "BACnet".to_string(),
        pattern: r"bacnet.*secure".to_string(),
        version_info: Some(VersionInfo {
            product: Some("BACnet Secure Connect".to_string()),
            version: None,
            info: Some("Secure BACnet".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("building-control".to_string()),
            cpe: vec!["cpe:/a:bacnet:bacnet_sc".to_string()],
        }),
        ports: vec![47808],
        protocol: "udp".to_string(),
    });

    // ========== OPC UA (OPC UNIFIED ARCHITECTURE) ==========

    // OPC UA Binary
    signatures.push(ServiceSignature {
        service_name: "opcua-binary".to_string(),
        probe_name: "OPCUA".to_string(),
        pattern: r"OPC.*UA|opc\.tcp".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OPC UA".to_string()),
            version: None,
            info: Some("Industrial communication protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:opcfoundation:opc_ua".to_string()],
        }),
        ports: vec![4840],
        protocol: "tcp".to_string(),
    });

    // OPC UA Discovery Server
    signatures.push(ServiceSignature {
        service_name: "opcua-discovery".to_string(),
        probe_name: "OPCUA".to_string(),
        pattern: r"OPC.*Discovery|urn:opcfoundation".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OPC UA Discovery Server".to_string()),
            version: None,
            info: Some("Server discovery service".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:opcfoundation:opc_ua".to_string()],
        }),
        ports: vec![4840],
        protocol: "tcp".to_string(),
    });

    // OPC UA over HTTPS
    signatures.push(ServiceSignature {
        service_name: "opcua-https".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"opc.*https".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OPC UA over HTTPS".to_string()),
            version: None,
            info: Some("Web service binding".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:opcfoundation:opc_ua".to_string()],
        }),
        ports: vec![443, 8443],
        protocol: "tcp".to_string(),
    });

    // ========== AMQP (ADVANCED MESSAGE QUEUING PROTOCOL) ==========

    // AMQP 0-9-1 (RabbitMQ)
    signatures.push(ServiceSignature {
        service_name: "amqp".to_string(),
        probe_name: "AMQP".to_string(),
        pattern: r"AMQP\x00\x00\x09\x01".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AMQP".to_string()),
            version: Some("0.9.1".to_string()),
            info: Some("Message queuing protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:amqp:amqp:0.9.1".to_string()],
        }),
        ports: vec![5672],
        protocol: "tcp".to_string(),
    });

    // AMQP 1.0
    signatures.push(ServiceSignature {
        service_name: "amqp1".to_string(),
        probe_name: "AMQP".to_string(),
        pattern: r"AMQP\x00\x01\x00\x00".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AMQP".to_string()),
            version: Some("1.0".to_string()),
            info: Some("OASIS standard protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:amqp:amqp:1.0".to_string()],
        }),
        ports: vec![5672],
        protocol: "tcp".to_string(),
    });

    // AMQP over WebSocket
    signatures.push(ServiceSignature {
        service_name: "amqp-ws".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Sec-WebSocket-Protocol:.*amqp".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AMQP over WebSocket".to_string()),
            version: None,
            info: Some("Browser-compatible AMQP".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:amqp:amqp".to_string()],
        }),
        ports: vec![5671, 15672],
        protocol: "tcp".to_string(),
    });

    // ========== DDS (DATA DISTRIBUTION SERVICE) ==========

    // DDS RTPS
    signatures.push(ServiceSignature {
        service_name: "dds-rtps".to_string(),
        probe_name: "DDS".to_string(),
        pattern: r"RTPS".to_string(),
        version_info: Some(VersionInfo {
            product: Some("DDS RTPS".to_string()),
            version: None,
            info: Some("Real-Time Publish Subscribe protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:omg:dds".to_string()],
        }),
        ports: vec![7400, 7401, 7410, 7411],
        protocol: "udp".to_string(),
    });

    // RTI Connext DDS
    signatures.push(ServiceSignature {
        service_name: "rti-dds".to_string(),
        probe_name: "DDS".to_string(),
        pattern: r"RTI.*Connext".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RTI Connext DDS".to_string()),
            version: None,
            info: Some("Industrial IoT connectivity".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:rti:connext_dds".to_string()],
        }),
        ports: vec![7400],
        protocol: "udp".to_string(),
    });

    // OpenDDS
    signatures.push(ServiceSignature {
        service_name: "opendds".to_string(),
        probe_name: "DDS".to_string(),
        pattern: r"OpenDDS".to_string(),
        version_info: Some(VersionInfo {
            product: Some("OpenDDS".to_string()),
            version: None,
            info: Some("Open source DDS implementation".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:opendds:opendds".to_string()],
        }),
        ports: vec![7400],
        protocol: "udp".to_string(),
    });

    // ========== INDUSTRIAL ETHERNET PROTOCOLS ==========

    // EtherNet/IP (Allen-Bradley)
    signatures.push(ServiceSignature {
        service_name: "ethernet-ip".to_string(),
        probe_name: "EtherNetIP".to_string(),
        pattern: r"\x6f\x00".to_string(),
        version_info: Some(VersionInfo {
            product: Some("EtherNet/IP".to_string()),
            version: None,
            info: Some("Industrial Ethernet protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:odva:ethernet_ip".to_string()],
        }),
        ports: vec![44818, 2222],
        protocol: "tcp".to_string(),
    });

    // PROFINET
    signatures.push(ServiceSignature {
        service_name: "profinet".to_string(),
        probe_name: "PROFINET".to_string(),
        pattern: r"PROFINET|PN-IO".to_string(),
        version_info: Some(VersionInfo {
            product: Some("PROFINET".to_string()),
            version: None,
            info: Some("Siemens industrial protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:profibus:profinet".to_string()],
        }),
        ports: vec![34962, 34963, 34964],
        protocol: "udp".to_string(),
    });

    // PROFINET DCP
    signatures.push(ServiceSignature {
        service_name: "profinet-dcp".to_string(),
        probe_name: "PROFINET".to_string(),
        pattern: r"DCP".to_string(),
        version_info: Some(VersionInfo {
            product: Some("PROFINET DCP".to_string()),
            version: None,
            info: Some("Discovery and Configuration Protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:profibus:profinet_dcp".to_string()],
        }),
        ports: vec![34964],
        protocol: "udp".to_string(),
    });

    // Siemens S7
    signatures.push(ServiceSignature {
        service_name: "s7comm".to_string(),
        probe_name: "S7".to_string(),
        pattern: r"\x03\x00\x00[\x16-\xff]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Siemens S7 Communication".to_string()),
            version: None,
            info: Some("PLC communication protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:siemens:s7".to_string()],
        }),
        ports: vec![102],
        protocol: "tcp".to_string(),
    });

    // ========== DNP3 (DISTRIBUTED NETWORK PROTOCOL) ==========

    // DNP3 TCP
    signatures.push(ServiceSignature {
        service_name: "dnp3-tcp".to_string(),
        probe_name: "DNP3".to_string(),
        pattern: r"\x05\x64".to_string(),
        version_info: Some(VersionInfo {
            product: Some("DNP3".to_string()),
            version: None,
            info: Some("Electric utility SCADA protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:ieee:dnp3".to_string()],
        }),
        ports: vec![20000],
        protocol: "tcp".to_string(),
    });

    // DNP3 UDP
    signatures.push(ServiceSignature {
        service_name: "dnp3-udp".to_string(),
        probe_name: "DNP3".to_string(),
        pattern: r"\x05\x64".to_string(),
        version_info: Some(VersionInfo {
            product: Some("DNP3 over UDP".to_string()),
            version: None,
            info: Some("Datagram-based DNP3".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:ieee:dnp3".to_string()],
        }),
        ports: vec![20000],
        protocol: "udp".to_string(),
    });

    // ========== IEC 60870-5-104 ==========

    // IEC 104
    signatures.push(ServiceSignature {
        service_name: "iec104".to_string(),
        probe_name: "IEC104".to_string(),
        pattern: r"\x68[\x04-\xff]".to_string(),
        version_info: Some(VersionInfo {
            product: Some("IEC 60870-5-104".to_string()),
            version: None,
            info: Some("Power system monitoring protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:iec:60870-5-104".to_string()],
        }),
        ports: vec![2404],
        protocol: "tcp".to_string(),
    });

    // ========== LWM2M (LIGHTWEIGHT M2M) ==========

    // LWM2M over CoAP
    signatures.push(ServiceSignature {
        service_name: "lwm2m".to_string(),
        probe_name: "LWM2M".to_string(),
        pattern: r"lwm2m".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LWM2M".to_string()),
            version: None,
            info: Some("Lightweight M2M for IoT device management".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:openmobilealliance:lwm2m".to_string()],
        }),
        ports: vec![5683, 5684],
        protocol: "udp".to_string(),
    });

    // Leshan LWM2M Server
    signatures.push(ServiceSignature {
        service_name: "leshan".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Leshan".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Eclipse Leshan".to_string()),
            version: None,
            info: Some("LWM2M server implementation".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:eclipse:leshan".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== ZIGBEE ==========

    // Zigbee Gateway
    signatures.push(ServiceSignature {
        service_name: "zigbee-gateway".to_string(),
        probe_name: "Zigbee".to_string(),
        pattern: r"zigbee|ZigBee".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zigbee Gateway".to_string()),
            version: None,
            info: Some("Wireless IoT protocol gateway".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:zigbee:zigbee".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Zigbee2MQTT
    signatures.push(ServiceSignature {
        service_name: "zigbee2mqtt".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"zigbee2mqtt".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Zigbee2MQTT".to_string()),
            version: None,
            info: Some("Zigbee to MQTT bridge".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:zigbee2mqtt:zigbee2mqtt".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== Z-WAVE ==========

    // Z-Wave Gateway
    signatures.push(ServiceSignature {
        service_name: "zwave-gateway".to_string(),
        probe_name: "ZWave".to_string(),
        pattern: r"z-wave|zwave".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Z-Wave Gateway".to_string()),
            version: None,
            info: Some("Smart home protocol gateway".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:zwave:zwave".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Z-Wave JS
    signatures.push(ServiceSignature {
        service_name: "zwave-js".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"zwave-js".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Z-Wave JS".to_string()),
            version: None,
            info: Some("Z-Wave driver for Node.js".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:zwave:zwave_js".to_string()],
        }),
        ports: vec![3000],
        protocol: "tcp".to_string(),
    });

    // ========== THREAD ==========

    // Thread Border Router
    signatures.push(ServiceSignature {
        service_name: "thread-border-router".to_string(),
        probe_name: "Thread".to_string(),
        pattern: r"thread.*border.*router".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Thread Border Router".to_string()),
            version: None,
            info: Some("IPv6-based IoT mesh network".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:thread:thread".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== MATTER (PROJECT CHIP) ==========

    // Matter Controller
    signatures.push(ServiceSignature {
        service_name: "matter".to_string(),
        probe_name: "Matter".to_string(),
        pattern: r"matter|project.*chip".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Matter".to_string()),
            version: None,
            info: Some("Smart home interoperability standard".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:csa:matter".to_string()],
        }),
        ports: vec![5540],
        protocol: "udp".to_string(),
    });

    // ========== LORAWAN ==========

    // LoRaWAN Network Server
    signatures.push(ServiceSignature {
        service_name: "lorawan-ns".to_string(),
        probe_name: "LoRaWAN".to_string(),
        pattern: r"LoRa.*Network.*Server|lorawan".to_string(),
        version_info: Some(VersionInfo {
            product: Some("LoRaWAN Network Server".to_string()),
            version: None,
            info: Some("Long-range IoT network".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:lora:lorawan".to_string()],
        }),
        ports: vec![1700],
        protocol: "udp".to_string(),
    });

    // ChirpStack
    signatures.push(ServiceSignature {
        service_name: "chirpstack".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"ChirpStack".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ChirpStack".to_string()),
            version: None,
            info: Some("LoRaWAN Network Server".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:chirpstack:chirpstack".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // The Things Network
    signatures.push(ServiceSignature {
        service_name: "ttn".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Things.*Network|TTN".to_string(),
        version_info: Some(VersionInfo {
            product: Some("The Things Network".to_string()),
            version: None,
            info: Some("LoRaWAN network infrastructure".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:thethingsnetwork:ttn".to_string()],
        }),
        ports: vec![1700, 8080],
        protocol: "tcp".to_string(),
    });

    // ========== KNX ==========

    // KNXnet/IP
    signatures.push(ServiceSignature {
        service_name: "knxnet-ip".to_string(),
        probe_name: "KNX".to_string(),
        pattern: r"\x06\x10".to_string(),
        version_info: Some(VersionInfo {
            product: Some("KNXnet/IP".to_string()),
            version: None,
            info: Some("Building automation protocol".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("building-control".to_string()),
            cpe: vec!["cpe:/a:knx:knxnet_ip".to_string()],
        }),
        ports: vec![3671],
        protocol: "udp".to_string(),
    });

    // ========== DALI ==========

    // DALI Gateway
    signatures.push(ServiceSignature {
        service_name: "dali-gateway".to_string(),
        probe_name: "DALI".to_string(),
        pattern: r"DALI".to_string(),
        version_info: Some(VersionInfo {
            product: Some("DALI Gateway".to_string()),
            version: None,
            info: Some("Digital Addressable Lighting Interface".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("building-control".to_string()),
            cpe: vec!["cpe:/a:dali:dali".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== ONVIF (OPEN NETWORK VIDEO INTERFACE) ==========

    // ONVIF Device
    signatures.push(ServiceSignature {
        service_name: "onvif".to_string(),
        probe_name: "ONVIF".to_string(),
        pattern: r"onvif".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ONVIF Device".to_string()),
            version: None,
            info: Some("IP camera/video device".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("camera".to_string()),
            cpe: vec!["cpe:/a:onvif:onvif".to_string()],
        }),
        ports: vec![80, 8080],
        protocol: "tcp".to_string(),
    });

    // RTSP (Real Time Streaming Protocol)
    signatures.push(ServiceSignature {
        service_name: "rtsp".to_string(),
        probe_name: "RTSP".to_string(),
        pattern: r"RTSP/1\.0".to_string(),
        version_info: Some(VersionInfo {
            product: Some("RTSP".to_string()),
            version: None,
            info: Some("Real-time video streaming".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("camera".to_string()),
            cpe: vec!["cpe:/a:rtsp:rtsp".to_string()],
        }),
        ports: vec![554, 8554],
        protocol: "tcp".to_string(),
    });

    // ========== INDUSTRIAL HMI ==========

    // Wonderware InTouch
    signatures.push(ServiceSignature {
        service_name: "wonderware-intouch".to_string(),
        probe_name: "Wonderware".to_string(),
        pattern: r"Wonderware|InTouch".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Wonderware InTouch".to_string()),
            version: None,
            info: Some("SCADA HMI software".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:aveva:wonderware_intouch".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // Ignition SCADA
    signatures.push(ServiceSignature {
        service_name: "ignition-scada".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Ignition.*SCADA".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Ignition SCADA".to_string()),
            version: None,
            info: Some("Industrial automation platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:inductiveautomation:ignition".to_string()],
        }),
        ports: vec![8088],
        protocol: "tcp".to_string(),
    });

    // ========== ROCKWELL AUTOMATION ==========

    // Allen-Bradley PLC
    signatures.push(ServiceSignature {
        service_name: "ab-plc".to_string(),
        probe_name: "EtherNetIP".to_string(),
        pattern: r"Allen.*Bradley|Rockwell".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Allen-Bradley PLC".to_string()),
            version: None,
            info: Some("Programmable Logic Controller".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/h:rockwellautomation:programmable_logic_controller".to_string()],
        }),
        ports: vec![44818],
        protocol: "tcp".to_string(),
    });

    // ========== SCHNEIDER ELECTRIC ==========

    // Modicon PLC
    signatures.push(ServiceSignature {
        service_name: "modicon-plc".to_string(),
        probe_name: "Modbus".to_string(),
        pattern: r"Modicon|Schneider".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Modicon PLC".to_string()),
            version: None,
            info: Some("Schneider Electric PLC".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/h:schneider_electric:modicon".to_string()],
        }),
        ports: vec![502],
        protocol: "tcp".to_string(),
    });

    // ========== ABB ==========

    // ABB 800xA
    signatures.push(ServiceSignature {
        service_name: "abb-800xa".to_string(),
        probe_name: "ABB".to_string(),
        pattern: r"ABB.*800xA".to_string(),
        version_info: Some(VersionInfo {
            product: Some("ABB 800xA".to_string()),
            version: None,
            info: Some("DCS automation system".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("scada".to_string()),
            cpe: vec!["cpe:/a:abb:800xa".to_string()],
        }),
        ports: vec![],
        protocol: "tcp".to_string(),
    });

    // ========== HOME AUTOMATION ==========

    // Home Assistant
    signatures.push(ServiceSignature {
        service_name: "homeassistant".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Home Assistant".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Home Assistant".to_string()),
            version: None,
            info: Some("Open source home automation".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:home_assistant:home_assistant".to_string()],
        }),
        ports: vec![8123],
        protocol: "tcp".to_string(),
    });

    // openHAB
    signatures.push(ServiceSignature {
        service_name: "openhab".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"openHAB".to_string(),
        version_info: Some(VersionInfo {
            product: Some("openHAB".to_string()),
            version: None,
            info: Some("Smart home automation platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:openhab:openhab".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // Node-RED
    signatures.push(ServiceSignature {
        service_name: "nodered".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Node-RED".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Node-RED".to_string()),
            version: None,
            info: Some("Flow-based programming for IoT".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:nodered:node-red".to_string()],
        }),
        ports: vec![1880],
        protocol: "tcp".to_string(),
    });

    // Domoticz
    signatures.push(ServiceSignature {
        service_name: "domoticz".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Domoticz".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Domoticz".to_string()),
            version: None,
            info: Some("Home automation system".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:domoticz:domoticz".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== MQTT BROKERS (ADDITIONAL) ==========

    // Mosquitto WebSockets
    signatures.push(ServiceSignature {
        service_name: "mosquitto-ws".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"mosquitto.*websocket".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Eclipse Mosquitto WebSocket".to_string()),
            version: None,
            info: Some("MQTT over WebSocket".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:eclipse:mosquitto".to_string()],
        }),
        ports: vec![9001],
        protocol: "tcp".to_string(),
    });

    // HiveMQ Control Center
    signatures.push(ServiceSignature {
        service_name: "hivemq-control-center".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"HiveMQ.*Control.*Center".to_string(),
        version_info: Some(VersionInfo {
            product: Some("HiveMQ Control Center".to_string()),
            version: None,
            info: Some("MQTT broker management UI".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:hivemq:control_center".to_string()],
        }),
        ports: vec![8080],
        protocol: "tcp".to_string(),
    });

    // ========== EDGE COMPUTING ==========

    // AWS IoT Greengrass
    signatures.push(ServiceSignature {
        service_name: "greengrass".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Greengrass".to_string(),
        version_info: Some(VersionInfo {
            product: Some("AWS IoT Greengrass".to_string()),
            version: None,
            info: Some("Edge computing runtime".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:amazon:iot_greengrass".to_string()],
        }),
        ports: vec![8000, 8443],
        protocol: "tcp".to_string(),
    });

    // Azure IoT Edge
    signatures.push(ServiceSignature {
        service_name: "azure-iot-edge".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"Azure.*IoT.*Edge".to_string(),
        version_info: Some(VersionInfo {
            product: Some("Azure IoT Edge".to_string()),
            version: None,
            info: Some("Edge computing platform".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:microsoft:azure_iot_edge".to_string()],
        }),
        ports: vec![443],
        protocol: "tcp".to_string(),
    });

    // EdgeX Foundry
    signatures.push(ServiceSignature {
        service_name: "edgex".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"EdgeX.*Foundry".to_string(),
        version_info: Some(VersionInfo {
            product: Some("EdgeX Foundry".to_string()),
            version: None,
            info: Some("IoT edge framework".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:edgexfoundry:edgex".to_string()],
        }),
        ports: vec![48080, 48081],
        protocol: "tcp".to_string(),
    });

    // K3s (Lightweight Kubernetes for IoT)
    signatures.push(ServiceSignature {
        service_name: "k3s".to_string(),
        probe_name: "GetRequest".to_string(),
        pattern: r"k3s".to_string(),
        version_info: Some(VersionInfo {
            product: Some("K3s".to_string()),
            version: None,
            info: Some("Lightweight Kubernetes for IoT/Edge".to_string()),
            hostname: None,
            os_type: None,
            device_type: Some("iot".to_string()),
            cpe: vec!["cpe:/a:rancher:k3s".to_string()],
        }),
        ports: vec![6443],
        protocol: "tcp".to_string(),
    });

    signatures
}
