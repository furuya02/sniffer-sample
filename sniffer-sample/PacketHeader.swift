//
//  PacketHeader.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/15.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class PacketHeader:NSObject{
    var _rawData:RawData
    var _offset:Int
    
    var buf = [Int8](count:128,repeatedValue:0) // 文字列化するためのテンポラリ
    
    init(_ rawData:RawData,offset:Int){
        _rawData = rawData;
        _offset = offset
    }
}
