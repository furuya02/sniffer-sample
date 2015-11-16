//
//  IcmpHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/16.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class IcmpHeader:PacketHeader{
    
    var Type:UInt8 = 0
    var Code:UInt8 = 0
    var CheckSum:UInt16 = 0
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset
        
        Type = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)
        
        Code = _rawData.memory(p) as UInt8
        p += sizeof(UInt8)

        CheckSum = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
    }
    
    override var description: String{
        get{
            var typeStr = ""
            switch Type {
                case 0:
                    typeStr = "Echo Reply"
                case 3:
                    typeStr = "Destination Unreachable"
                case 4:
                    typeStr = "Souce Quench"
                case 5:
                    typeStr = "Redirect"
                case 8:
                    typeStr = "Echo Request"
                case 11:
                    typeStr = "Time Exceeded"
                default:
                    typeStr = String(format: "Type:0x%2.2x",Type)
            }
            return String(format: "%@ Code:0x%2.2x",typeStr,Code)
        }
    }
}