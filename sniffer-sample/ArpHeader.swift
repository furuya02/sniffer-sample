//
//  ArpHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/15.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class ArpHeader:PacketHeader{
    
    var HardwareType:UInt16 = 0
    var ProtocolType:UInt16 = 0
    var HardwareAddressLength:UInt8 = 0
    var ProtocolAddressLength:UInt8 = 0
    var Opcode:UInt16 = 0
    var SourceHardwareAddress = ""
    var SourceProtocolAddress = ""
    var DestnationHardwareAddress = ""
    var DestnationProtocolAddress = ""
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset

        HardwareType = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        ProtocolType = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        HardwareAddressLength = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        ProtocolAddressLength = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        Opcode = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        let srcHwAddr:UnsafePointer<ether_addr> = _rawData.ptr(p)
        SourceHardwareAddress = String.fromCString(ether_ntoa(srcHwAddr))!
        p += Int(HardwareAddressLength)

        var srcAddr = _rawData.memory(p) as UInt32
        inet_ntop(AF_INET,&srcAddr,&buf,128)
        SourceProtocolAddress = String.fromCString(buf)!
        p += Int(ProtocolAddressLength)

        let dstHwAddr:UnsafePointer<ether_addr> =  _rawData.ptr(p)
        DestnationHardwareAddress = String.fromCString(ether_ntoa(dstHwAddr))!
        p += Int(HardwareAddressLength)

        var dstAddr = _rawData.memory(p) as UInt32
        inet_ntop(AF_INET,&dstAddr,&buf,128)
        DestnationProtocolAddress = String.fromCString(buf)!
        p += Int(ProtocolAddressLength)

    }
    
    override var description: String{
        get{
            if(Opcode==1){
                return "ARP Opcode:\(Opcode) Request where is \(DestnationProtocolAddress) from \(SourceProtocolAddress)"
            }else if(Opcode==2){
                return "ARP Opcode:\(Opcode) Replay \(SourceProtocolAddress) is \(SourceHardwareAddress) to \(DestnationProtocolAddress)"
            }else{
                return "ARP Opcode:\(Opcode) "
            }
        }
    }
    
    
}

