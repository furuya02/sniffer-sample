//
//  RawData.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/15.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

class RawData:NSObject{
    var _data:NSData
    
    // ポインタと長さで初期化
    // Unsafepointer<Void>で指定された領域のデータをNSDataで保持する
    init(_ data:UnsafePointer<Void>, length:Int ) {
        self._data = NSData(bytes: data, length: length)
    }
    
    // 型を指定して構造体を取得（オフセット指定あり）
    func memory<T>(offset: Int) -> T {
        //指定されたoffset以降のポインタを得る
        let p = self._data.subdataWithRange(NSMakeRange(offset, sizeof(T))).bytes
        // 指定された型にキャストする
        return UnsafePointer<T>(p).memory
    }
    
    // 型を指定してポインタを取得（オフセット指定あり）
    func ptr<T>(offset: Int) -> UnsafePointer<T> {
        //指定されたoffset以降のポインタを得る
        let p = self._data.subdataWithRange(NSMakeRange(offset, sizeof(T))).bytes
        // 指定された型にキャストする
        return UnsafePointer<T>(p)
    }
    
    // サイズを指定してUnsafePointer<UInt8>を取得する
    func ptr(offset: Int, length:Int) -> UnsafePointer<UInt8> {
        //指定されたoffset以降のポインタを得る
        let p = self._data.subdataWithRange(NSMakeRange(offset, length)).bytes
        // UInt8へのポインタにキャストする
        return UnsafePointer<UInt8>(p)
    }
    
    
    // 型を指定して直接キャストする（クラスメソッド）
    class func direct<T>(data:UnsafePointer<Void>) -> T{
        let d = NSData(bytes: data, length: sizeof(T))
        return UnsafePointer<T>(d.bytes).memory
    }
}


