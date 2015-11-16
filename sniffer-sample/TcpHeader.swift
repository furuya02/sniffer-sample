//
//  TcpHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/16.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class TcpHeader:PacketHeader{
    
    var SourcePort:UInt16 = 0
    var DestnationPort:UInt16 = 0
    var SquenceNumber:UInt32 = 0
    var AcknowledgementNumber:UInt32 = 0
    var DataOffset:UInt8 = 0 //4bit
    var ControlFlg:UInt8 = 0
    var WindowSize:UInt16 = 0
    var Checksum:UInt16 = 0
    var UrgentPointer:UInt16 = 0

    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset
        
        SourcePort = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)

        DestnationPort = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
        SquenceNumber = (_rawData.memory(p) as UInt32).bigEndian
        p += sizeof(UInt32)

        AcknowledgementNumber = (_rawData.memory(p) as UInt32).bigEndian
        p += sizeof(UInt32)
        
        let n = _rawData.memory(p) as UInt8
        DataOffset = (n & 0xF0)>>4
        p += sizeof(UInt8)
        
        ControlFlg = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        WindowSize = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)

        Checksum = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)

        UrgentPointer = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
    }
    
    override var description: String{
        get{
            return String(format: "srcPort:%d dstPort:%d Squence:%4.4x Ack:%4.4x Checksum:%4.4x WindowSize:%d",SourcePort,DestnationPort,SquenceNumber,AcknowledgementNumber,Checksum,WindowSize)
        }
    }
}



