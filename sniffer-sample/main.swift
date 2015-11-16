//
//  main.swift
//  sniffer-sample
//
//  Created by ShinichiHirauchi on 2015/11/13.
//  Copyright © 2015年 SAPPOROWORKS. All rights reserved.
//

import Foundation

///////////////////////////////////////////////////
// デバイス列挙
///////////////////////////////////////////////////
var errbuf = [Int8](count:Int(PCAP_ERRBUF_SIZE),repeatedValue:0) // エラー情報を受け取るためのバッファ
var allDevs = UnsafeMutablePointer<pcap_if>()//.alloc(1) // デバイス情報を受け取るためのポインタ
var buf = [Int8](count:128,repeatedValue:0) // IPアドレスを文字列化するためのバッファ
var devs = Array<String>() // 名前の一覧を作成する
var no = 0 // 選択番号

//pcap_findalldevs(<#T##UnsafeMutablePointer<UnsafeMutablePointer<pcap_if_t>>#>, <#T##UnsafeMutablePointer<Int8>#>)
if ( pcap_findalldevs(&allDevs,UnsafeMutablePointer<CChar>(errbuf)) != -1 ){
    
    for(var dev = allDevs.memory ;; dev = dev.next.memory){
        
        // デバイス名の表示
        var name = String.fromCString(dev.name)!
        devs.append(name)

        // 選択番号とデバイス名を表示する
        print("[\(no++). \(name)]")
        // 選択を補助するための、設定されているIPアドレスを表示する
        for(var p = dev.addresses ;; p = p.memory.next){
            let famiry = Int32(p.memory.addr.memory.sa_family)
            if(famiry == AF_INET){ //IPv4
                var sockaddrIn = RawData.direct(p.memory.addr) as sockaddr_in
                inet_ntop(AF_INET,&sockaddrIn.sin_addr,&buf,128)
                print("  " + String.fromCString(buf)!)
            }else if(famiry == AF_INET6){//IPv6
                var sockaddrIn6 = RawData.direct(p.memory.addr) as sockaddr_in6
                inet_ntop(AF_INET6,&sockaddrIn6.sin6_addr,&buf,128)
                print("  " + String.fromCString(buf)!)
            }else{ //Other
                
            }

            // 次の情報(pcap_addr)が無い場合は、ループを終了する
            if(p.memory.next == nil){
                break
            }
        }
        
        // 次のデバイス情報(1pcap_if)が無い場合は、ループを終了する
        if(dev.next == nil){
            break
        }
    }
}
pcap_freealldevs(allDevs);
//allDevs.dealloc(1)


///////////////////////////////////////////////////
// デバイスの選択
///////////////////////////////////////////////////

var devNo:Int = 0
while(true){
    print("モニタするデバイスの番号を入力して下さい \(0)〜\(devs.count-1) : ", terminator: "")
    var n = Int(getchar() - 48)
    rewind(stdin) // Enter排除
    if 0 <= n && n < devs.count {
        devNo = n
        break
    }
}

print("selected: \(devs[devNo])")




///////////////////////////////////////////////////
// パケット取得
///////////////////////////////////////////////////

var error: UnsafeMutablePointer<CChar> = nil
var descr = pcap_create(devs[devNo],error)

//if(pcap_set_promisc(descr, 1) != 0){
//    print("Error pcap_set_promisc")
//    exit(-1)
//}
//
//if(pcap_set_rfmon(descr, 1) != 0 ){
//    print("Error pcap_set_rfmon")
//    exit(-1)
//}
let MAX_RECV_SIZE:Int32 = 65535 // 受信バッファのサイズ
let Promisc:Int32 = 0
let timeout:Int32 = 500
var handle = pcap_open_live(devs[devNo], MAX_RECV_SIZE, Promisc, timeout,&errbuf);
if (handle == nil) {
        NSLog("Can not open device \(String.fromCString(errbuf)!)");
        exit(2);
}

var pkt_hdr = UnsafeMutablePointer<pcap_pkthdr>() // pcapヘッダ情報取得用バッファ
var pkt_data = UnsafePointer<u_char>() // パケットデータ取得用バッファ
var frameNo = 0
while(true){
    var res = pcap_next_ex(handle, &pkt_hdr, &pkt_data)
    if(res <= 0){
        if(res < 0 ){
            print("ERROR!")
        }else{
            // res=0 の場合は、受信データがなくタイムアウトしただけなので処理なし
        }
        continue;
    }
    var rawData = RawData(pkt_data, length: Int(pkt_hdr.memory.caplen))
    
    // パケット情報の表示
    var tv_sec = Double(pkt_hdr.memory.ts.tv_sec) + 60*60*9 // +0900
    var sec = Int(tv_sec % 60)
    tv_sec /= 60
    var min = Int(tv_sec % 60)
    tv_sec /= 60
    var hour = Int(tv_sec % 24)
    print(NSString(format: "Frame %d: %dbyte %02d:%02d:%02d.%06ld"
        , frameNo++
        , pkt_hdr.memory.caplen
        , hour
        , min
        , sec
        , pkt_hdr.memory.ts.tv_usec));
    

    var offset = 0
    
    // Etherヘッダ情報の表示
    var etherHeader = EtherHeader(rawData,offset: offset)
    print(etherHeader)

    offset+=14 // Etherヘッダ分だけオフセットを移動する
    
    //print(NSString(format: "DestnationAddress = %@",etherHeader.DestnationAddress))
    //print(NSString(format: "SourceAddress = %@",etherHeader.SourceAddress))
    //print(NSString(format: "Type = 0x%4.4x",etherHeader.Type))
        
    if(etherHeader.Type == 0x0806){ //ARP
        // ARPヘッダ情報の表示
        var arpHeader = ArpHeader(rawData,offset:offset)
        print("  ", terminator: "") // インデント
        print(arpHeader)
            
        //print(NSString(format: "HardwareType = %4.4x",arpHeader.HardwareType))
        //print(NSString(format: "ProtocolType = %4.4x",arpHeader.ProtocolType))
        //print(NSString(format: "HardwareAddressLength = %4.4x",arpHeader.HardwareAddressLength))
        //print(NSString(format: "ProtocolAddressLength = %4.4x",arpHeader.ProtocolAddressLength))
        //print(NSString(format: "Opcode = %4.4x",arpHeader.Opcode))
        //print(NSString(format: "SourceHardwareAddress = %@",arpHeader.SourceHardwareAddress))
        //print(NSString(format: "SourceProtocolAddress = %@",arpHeader.SourceProtocolAddress))
        //print(NSString(format: "DestnationHardwareAddress = %@",arpHeader.DestnationHardwareAddress))
        //print(NSString(format: "DestnationProtocolAddress = %@",arpHeader.DestnationProtocolAddress))
    }else if(etherHeader.Type == 0x0800){ // IP
        // IPヘッダ情報の表示
        var ipHeader = IpHeader(rawData,offset:offset)
        print("  ", terminator: "") // インデント
        print(ipHeader)

        offset += Int(ipHeader.HeaderLength) // IPヘッダ分だけオフセットを移動する
            
        if( ipHeader.Protocol == 0x01){ // ICMP
            // ICMPヘッダ情報の表示
            var icmpHeader = IcmpHeader(rawData,offset:offset)
            print("  ", terminator: "") // インデント
            print(icmpHeader)
        }else if(ipHeader.Protocol == 0x06){ //TCP
            // TCPヘッダ情報の表示
            var tcpHeader = TcpHeader(rawData,offset:offset)
            print("  ", terminator: "") // インデント
            print(tcpHeader)
        
        }else if(ipHeader.Protocol == 0x11){ //UDP
            // DPヘッダ情報の表示
            var udpHeader = UdpHeader(rawData,offset:offset)
            print("  ", terminator: "") // インデント
            print(udpHeader)
        }
    }else if(etherHeader.Type == 0x86dd){ // IPv6
        // IPv6ヘッダ情報の表示
        var ipv6Header = Ipv6Header(rawData,offset:offset)
        print("  ", terminator: "") // インデント
        print(ipv6Header)
    }
}
pcap_close(handle) // 現状、強制終了しか用意していないので、ここは通らない・・・





