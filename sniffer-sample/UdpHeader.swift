//
//  UdpHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/16.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class UdpHeader:PacketHeader{
    
    var SourcePort:UInt16 = 0
    var DestnationPort:UInt16 = 0
    var Length:UInt16 = 0
    var Checksum:UInt16 = 0
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset
        
        SourcePort = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        DestnationPort = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)

        Length = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        Checksum = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        
    }
    
    override var description: String{
        get{
            return String(format: "srcPort:%d dstPort:%d length:%d Checksum:%4.4x",SourcePort,DestnationPort,Length,Checksum)
        }
    }
}

