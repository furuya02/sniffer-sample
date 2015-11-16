//
//  IpHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/16.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class IpHeader:PacketHeader{
    
    var Version:UInt8 = 0 // 4bit
    var HeaderLength:UInt8 = 0 // 4bit
    var TypeOfService:UInt8 = 0
    var TotalLength:UInt16 = 0
    var Identification:UInt16 = 0
    var Flags_FlagmentOffset:UInt16 = 0
    var TimeToLive:UInt8 = 0
    var Protocol:UInt8 = 0
    var HeaderChecksum:UInt16 = 0
    var SourceAddress = "" //32bit
    var DestnationAddress = "" //32bit
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset
        
        let n = _rawData.memory(p) as UInt8
        Version = (n & 0xF0)>>4
        HeaderLength = (n & 0x0F)*4
        
        p += sizeof(UInt8)

        TypeOfService = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        TotalLength = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        Identification = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        
        Flags_FlagmentOffset = _rawData.memory(p) as UInt16
        p += sizeof(UInt16)

        TimeToLive = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)

        Protocol = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)

        HeaderChecksum = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)

        var srcAddr = _rawData.memory(p) as UInt32
        inet_ntop(AF_INET,&srcAddr,&buf,128)
        SourceAddress = String.fromCString(buf)!
        p += sizeof(UInt32)

        var dstAddr = _rawData.memory(p) as UInt32
        inet_ntop(AF_INET,&dstAddr,&buf,128)
        DestnationAddress = String.fromCString(buf)!
        p += sizeof(UInt32)
        
    }
    
    override var description: String{
        get{
            var protocolStr = ""
            
            switch Protocol {
                case 0x06:
                    protocolStr = "TCP"
                case 0x11:
                    protocolStr = "UDP"
                case 0x01:
                    protocolStr = "ICMP"
                default:
                    protocolStr = String(format: "Protocol:0x%2.2x",Protocol)
            }
            
            return "\(protocolStr)  src:\(SourceAddress) dst:\(DestnationAddress) TTL:\(TimeToLive) len:\(HeaderLength)"
        }
    }
}

