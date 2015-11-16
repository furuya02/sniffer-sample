//
//  Ipv6Header.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/16.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class Ipv6Header:PacketHeader{
    
    var Version:UInt8 = 0 // 4bit
    var PayloadLength:UInt16 = 0
    var NextHeader:UInt8 = 0
    var HopLimit:UInt8 = 0
    var SourceAddress = "" //128bit
    var DestnationAddress = "" //128bit
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset
        
        let n = _rawData.memory(p) as UInt8
        Version = (n & 0xF0) >> 4

        p += sizeof(UInt32)
        
        
        PayloadLength = _rawData.memory(p) as UInt16
        p += sizeof(UInt16)
        
        NextHeader = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)

        HopLimit = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        let srcAddr = _rawData.ptr(p,length: 16)
        SourceAddress = v6Addr(srcAddr)
        p += 16

        let dstAddr = _rawData.ptr(p,length: 15)
        DestnationAddress = v6Addr(dstAddr)
        p += 16

    }
    
    func v6Addr(addr:UnsafePointer<UInt8>) -> String{
        return String(format: "%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x:%2.2x%2.2x"
            ,addr[0],addr[1],addr[2],addr[3]
            ,addr[4],addr[5],addr[6],addr[7]
            ,addr[8],addr[9],addr[10],addr[11]
            ,addr[12],addr[13],addr[14],addr[15]
        )
    }
    
    override var description: String{
        get{
            return String(format: "src:%@ dst:%@ HopLimit:%d",SourceAddress,DestnationAddress,HopLimit)
        }
    }
}

