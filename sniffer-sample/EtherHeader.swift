//
//  EtherHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/15.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class EtherHeader:PacketHeader{
    
    var DestnationAddress = ""
    var SourceAddress = ""
    var Type:UInt16 = 0
    
    
    override init(_ rawData:RawData,offset:Int){
        super.init(rawData,offset: offset)
        
        var p = _offset

        let dstAddr:UnsafePointer<ether_addr> = _rawData.ptr(p)
        DestnationAddress =  String.fromCString(ether_ntoa(dstAddr))!
        p += 6

        let srcAddr:UnsafePointer<ether_addr> = _rawData.ptr(p)
        SourceAddress =  String.fromCString(ether_ntoa(srcAddr))!
        p += 6
        
        Type = (_rawData.memory(p) as UInt16).bigEndian
        p += sizeof(UInt16)
        
    }
    
    override var description: String{
        get{
            var typeStr = ""
            if(Type==0x0800){
                typeStr = "IP"
            }else if(Type==0x0806){
                    typeStr = "ARP"
            }else if(Type==0x086dd){
                typeStr = "IPv6"
            }
            return String(format:"dst:%@ src:%@ type:0x%4.4x(%@)",DestnationAddress,SourceAddress,Type,typeStr)
        }
    }
}
