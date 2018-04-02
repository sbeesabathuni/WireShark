/**
 * Created by parallels on 3/2/18.
 */

import org.jnetpcap.*;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.util.*;


public class analysis_pcap_tcp {

  public static Map<String,Integer> tcpMap = new HashMap<String,Integer>();
  public static int tcpOpen = 0;
  public static int tcpClose = 0;
  public static int tcpCount = 0;
  public static List<TCPDataPacket> allTCPPackets = new ArrayList<TCPDataPacket>();
  public static List<Integer> destPorts = new ArrayList<Integer>();
  public static long ssthreshold = 0;
  public static List<Double> rttList = new ArrayList<Double>();
  public static long cwind = 1460; // 1 MSS (Typical MSS has a value of 1460)
  public static HashMap<Integer,List<TCPDataPacket>> sourceMap = new HashMap<Integer,List<TCPDataPacket>>();
  public static HashMap<Long,List<TCPDataPacket>> sourceSeqMap = new HashMap<Long,List<TCPDataPacket>>();
  public static HashMap<Long,List<TCPDataPacket>> receiveSeqMap = new HashMap<Long,List<TCPDataPacket>>();
  public static int totalPackets = 0;
  public static HashMap<Integer,List<TCPDataPacket>> receiveMap = new HashMap<Integer,List<TCPDataPacket>>();
  public static List<Integer> destinationPorts = new ArrayList<Integer>();
  public static void main(String args[]) {

    try {
      PrintStream out = new PrintStream(new FileOutputStream("output_b.txt"));
      System.setOut(out);
    } catch (FileNotFoundException e) {

    }

    tcpMap.put("sourcePort",0);
    tcpMap.put("destPort",2);
    tcpMap.put("seqNum",4);
    tcpMap.put("ackNum",8);
    tcpMap.put("dataOffset",12);
    tcpMap.put("flag",13);
    tcpMap.put("window",14);
    tcpMap.put("checkSum",16);
    tcpMap.put("urgent",18);

    final StringBuilder errbuf = new StringBuilder();

    final Pcap pcap = Pcap.openOffline("assignment2.pcap", errbuf);
    //final Pcap pcap = Pcap.openOffline("http_test_1080.pcap", errbuf);
    System.out.println(pcap);
    if (pcap == null) {
      System.err.println(errbuf.toString());
      return;
    }
    pcap.loop(Pcap.LOOP_INFINITE, new JPacketHandler<StringBuilder>() {
      public void nextPacket(JPacket packet, StringBuilder errbuf) {
        totalPackets++;
        byte[] packetData = packet.getByteArray(0, packet.size());
        // Removing first 34 bytes : Ethernet(14 bytes)+IP Header(20 bytes)
        byte[] requiredPacketData = Arrays.copyOfRange(packetData, 34, packetData.length);
        TCPDataPacket packetInfo = setTCPDataFromByteArray(requiredPacketData);

        double timeStamp = packet.getCaptureHeader().timestampInMillis();
        packetInfo.setTimeStamp(timeStamp);
        double totalBytes = packetData.length;
        packetInfo.setPacketLength(totalBytes);
        //allTCPPackets.add(packetInfo);

        ssthreshold = Math.max(ssthreshold, packetInfo.getWindow()); // setting it to largest window size

//        System.out.println("Source : "+packetInfo.getSourcePort() + " Destn : "+packetInfo.getDestPort() +
//            " Seq : "+packetInfo.getSeqNumber() + " Ack : "+packetInfo.getAckNumber() + " Flag :"+packetInfo.getFlag());
        //System.out.println(" Data offset :" + packetInfo.getDataOffset());
        if (packetInfo.getFlag() == 2) { //SYN
          //System.out.println("open");
          tcpOpen++;
          receiveMap.put(packetInfo.getSourcePort(), new ArrayList<TCPDataPacket>());
          destinationPorts.add(packetInfo.getDestPort());
//          System.out.println("Source : "+packetInfo.getSourcePort() + " Destn : "+packetInfo.getDestPort() +
//              " Seq : "+packetInfo.getSeqNumber() + " Ack : "+packetInfo.getAckNumber());
        } else if (packetInfo.getFlag() == 17 && destinationPorts.indexOf(packetInfo.getSourcePort()) > -1) { //FIN_ACK
          //System.out.println("close");
//          System.out.println("Source : "+packetInfo.getSourcePort() + " Destn : "+packetInfo.getDestPort() +
//              " Seq : "+packetInfo.getSeqNumber() + " Ack : "+packetInfo.getAckNumber());
          List<TCPDataPacket> currentPacketList = receiveMap.get(packetInfo.getDestPort());
          //System.out.println(currentPacketList);
          currentPacketList.add(packetInfo);
          receiveMap.put(packetInfo.getDestPort(), currentPacketList);
          tcpClose++;
        } else if (destinationPorts.indexOf(packetInfo.getSourcePort()) > -1){
          //System.out.println(packetInfo.getSourcePort());
          List<TCPDataPacket> currentPacketList = receiveMap.get(packetInfo.getDestPort());
          //System.out.println(currentPacketList);
          if (currentPacketList == null) {
            currentPacketList = new ArrayList<TCPDataPacket>();
          }
          currentPacketList.add(packetInfo);
          receiveMap.put(packetInfo.getDestPort(), currentPacketList);
        }
        setSourceMap(packetInfo);
      }
    },errbuf);

    while (tcpOpen > 0 && tcpClose > 0) {
      tcpCount++;
      tcpOpen--;
      tcpClose--;
    }
    //System.out.println(receiveMap.get());
    System.out.println("Total number of packets in pcap file : "+totalPackets);
    System.out.println("Total Number of TCP Flows initiated by the sender = "+tcpCount);
    getTCPFlowDetails();
    congestionControl();
    pcap.close();
  }

  public static TCPDataPacket setTCPDataFromByteArray(byte[] packetData) {
    TCPDataPacket tcpPacket = new TCPDataPacket();
    byte[] sourceByte = Arrays.copyOfRange(packetData, tcpMap.get("sourcePort"), tcpMap.get("sourcePort") + 2);
    tcpPacket.setSourcePort(bytetoInt(sourceByte));
    byte[] destByte = Arrays.copyOfRange(packetData, tcpMap.get("destPort"), tcpMap.get("destPort") + 2);
    tcpPacket.setDestPort(bytetoInt(destByte));
    byte[] seqNumByte = Arrays.copyOfRange(packetData, tcpMap.get("seqNum"), tcpMap.get("seqNum") + 4);
    tcpPacket.setSeqNumber(byteToLong(seqNumByte));
    byte[] ackNumByte = Arrays.copyOfRange(packetData, tcpMap.get("ackNum"), tcpMap.get("ackNum") + 4);
    tcpPacket.setAckNumber(byteToLong(ackNumByte));
    byte[] flagByte = Arrays.copyOfRange(packetData, tcpMap.get("flag"), tcpMap.get("flag") + 1);
    tcpPacket.setFlag(bytetoInt(flagByte));
    byte[] windowByte = Arrays.copyOfRange(packetData, tcpMap.get("window"), tcpMap.get("window") + 2);
    tcpPacket.setWindow(bytetoInt(windowByte));
    byte[] checkSumByte = Arrays.copyOfRange(packetData, tcpMap.get("checkSum"), tcpMap.get("checkSum") + 2);
    tcpPacket.setCheckSum(bytetoInt(checkSumByte));
    byte[] urgentByte = Arrays.copyOfRange(packetData, tcpMap.get("urgent"), tcpMap.get("urgent") + 2);
    tcpPacket.setUrgent(bytetoInt(urgentByte));
    return tcpPacket;
  }

  public static int bytetoInt( byte[] bytes ) {
//    if (bytes.length == 4)
//      return bytes[0] << 24 | (bytes[1] & 0xff) << 16 | (bytes[2] & 0xff) << 8
//          | (bytes[3] & 0xff);
//    else if (bytes.length == 3)
//      return 0x00 << 24 | (bytes[0] & 0xff) << 16 | (bytes[1] & 0xff) << 8 | (bytes[2] & 0xff);
//    else
      if (bytes.length == 2)
        return 0x00 << 24 | 0x00 << 16 | (bytes[0] & 0xff) << 8 | (bytes[1] & 0xff);
      else if (bytes.length == 1)
        return 0x00 << 24 | 0x00 << 16 | 0x00 << 8 | (bytes[0] & 0xff);

    return 0;
  }

  public static long byteToLong(byte[] bytes) {
    return ((long)(bytes[0] & 0xff) << 24) | ((long)(bytes[1] & 0xff) << 16)
        | ((long)(bytes[2] & 0xff) << 8) | (0x000000FFL & bytes[3]);
  }


  public static void setSourceMap(TCPDataPacket packet) {
    int sourcePort = packet.getSourcePort();
    int destPort = packet.getDestPort();
    long seqNum = packet.getSeqNumber();
    long ackNum = packet.getAckNumber();
    int tcpFlag = packet.getFlag();
    if (!sourceMap.containsKey(sourcePort) && destPorts.indexOf(sourcePort) < 0) {
      List<TCPDataPacket> allpackets = new ArrayList<TCPDataPacket>();
      allpackets.add(packet);
      sourceMap.put(sourcePort,allpackets);
      if (destPorts.indexOf(destPort) < 0) {
        destPorts.add(destPort);
      }
    } else if (destPorts.indexOf(sourcePort) < 0){
      List<TCPDataPacket> allpackets = sourceMap.get(sourcePort);
      allpackets.add(packet);
      sourceMap.put(sourcePort,allpackets);
    }

  }

  public static void getTCPFlowDetails() {
    List keys = new ArrayList(sourceMap.keySet());
    for (int i=0;i<keys.size();i++) {
      System.out.println((Integer)keys.get(i));
    }
   for (int i=0;i<sourceMap.size();i++) {
 //   for (int i=0;i<1;i++){
      boolean synAck = false;
      int counter = 0;
      float receivedPackets = 0;
      int currentSourcePort = (Integer)keys.get(i);
      double averageRTT = 0.0d;
      List<TCPDataPacket> currentTCPList = sourceMap.get(currentSourcePort);
      double currentSentPacketsLength = 0.0d;
      double currentSentPacketsTime = 0.0d;
      System.out.println("=======================TCP Flow "+(i+1)+" for "+currentSourcePort+" ============================");
      for (TCPDataPacket packet: receiveMap.get(currentSourcePort)) {
        int sourcePort = packet.getSourcePort();
        int destPort = packet.getDestPort();
        long seqNum = packet.getSeqNumber();
        long ackNum = packet.getAckNumber();
        int windowSize = packet.getWindow();
        int tcpFlag = packet.getFlag();
        if (tcpFlag == 18) { //SYN_ACK
          synAck = true;
        } else {
          if (synAck & currentSourcePort == destPort) {
              for (int j = 0; j < currentTCPList.size(); j++) {
                TCPDataPacket currentPacket = currentTCPList.get(j);
                if (seqNum == currentPacket.getAckNumber() && ackNum == currentPacket.getSeqNumber()) {
                  if (!receiveSeqMap.containsKey(currentPacket.getSeqNumber())) {
                    List<TCPDataPacket> rList = new ArrayList<TCPDataPacket>();
                    rList.add(packet);
                    receiveSeqMap.put(currentPacket.getSeqNumber(), rList);
                  } else {
                    List<TCPDataPacket> rList = receiveSeqMap.get(currentPacket.getSeqNumber());
                    rList.add(packet);
                    receiveSeqMap.put(currentPacket.getAckNumber(), rList);
                  }
                  double sentPacketTS = currentPacket.getTimeStamp();
                  double receivedPacketTS = packet.getTimeStamp();
                  averageRTT = 0.875*averageRTT + 0.125*(receivedPacketTS-sentPacketTS);
                  if(counter < 2) {
                    System.out.println("Transaction " + (counter + 1) + " :");
                    System.out.println("Source : " + currentPacket.getSourcePort() + " Destn : " + currentPacket.getDestPort() +
                        " Seq : " + currentPacket.getSeqNumber() + " Ack : " + currentPacket.getAckNumber() + " Window size :" + currentPacket.getWindow());
                    System.out.println("Source : " + sourcePort + " Destn : " + destPort +
                        " Seq : " + seqNum + " Ack : " + ackNum + " Window size :" + windowSize);
                    counter++;

                  }
                }

              }

          }
        }

      }
      //to calculate empirical throughput
      for (int j = 0; j < currentTCPList.size(); j++) {
        //System.out.println(currentTCPList.get(j).getTimeStamp());
        currentSentPacketsLength += currentTCPList.get(j).getPacketLength();
        if (j > 0) {
          currentSentPacketsTime += currentTCPList.get(j).getTimeStamp() - currentTCPList.get(j-1).getTimeStamp();
        }

      }
      System.out.println("currentSentPacketsTime : "+currentSentPacketsTime);
      System.out.println("currentSentPacketsLength : "+currentSentPacketsLength);
      currentSentPacketsTime = currentSentPacketsTime / 1000; //convert to seconds
      currentSentPacketsLength = currentSentPacketsLength * 0.000008; // convert byte to mega bits
      //
      float noOfPacketsSent = sourceMap.get(currentSourcePort).size() - 2; // removing SYN and SYN_ACK
      receivedPackets = receiveMap.get(currentSourcePort).size() - 1; // removing FIN_ACK
      System.out.println();
      System.out.println("No of Packets Sent :"+noOfPacketsSent);
      System.out.println("No of Received Packets :"+receivedPackets);
      float lossRate = (noOfPacketsSent - receivedPackets) / noOfPacketsSent;
      double eTput = currentSentPacketsLength / currentSentPacketsTime;
      //Empirical Throughput
      System.out.println("Empirical Throughput :"+ eTput +" Mb/s");
      //Loss Rate of Tcp flow
      System.out.println("LossRate = "+lossRate);
      // Average RTT of TCP flow
      System.out.println("Average RTT :"+averageRTT+" ms");
      //Theoretical throughput = 1.22*MSS/RTT* sqrt (L)
     // Typical MSS has a value of 1460
     double theoreticalTput = (1.22*1460*0.000008*1000)/(averageRTT*Math.sqrt(lossRate));
     System.out.println("Theoretical Throughput :"+ theoreticalTput +" Mb/s");
     rttList.add(averageRTT);

    }
  }

  public static void congestionControl() {
    System.out.println("======PART B===============");
    List keys = new ArrayList(sourceMap.keySet());
    for (int i=0;i<sourceMap.size();i++) {
      long currentssthreshold = ssthreshold; // largest window size
      long icwind = 1460;
      long cwind = icwind;
      List<Long> cWindList = new ArrayList<Long>();
      List<TCPDataPacket> currentSentPackets = sourceMap.get((Integer)keys.get(i));
      Double timeOutLimit = 2 * rttList.get(i);
      int timeoutRetransimission = 0;
      int tripleAckRetransimission = 0;
      for (int j=0;j<currentSentPackets.size();j++) {
        TCPDataPacket currPacket = currentSentPackets.get(j);
        for (int k=0; k<j;k++) {
          TCPDataPacket prevPacket = currentSentPackets.get(k);
          if (currPacket.getSeqNumber() == prevPacket.getSeqNumber()) {
            if (currPacket.getTimeStamp() - prevPacket.getTimeStamp() > timeOutLimit) {
              timeoutRetransimission++;
              currentssthreshold = cwind/2;
              cwind = icwind;
            } else {//check for triple ack
                if (receiveSeqMap.containsKey(currPacket.getSeqNumber())
                    && receiveSeqMap.get(currPacket.getSeqNumber()).size() >=3) {
                  tripleAckRetransimission++;
                  currentssthreshold = cwind/2;
                  cwind = icwind;
                }
            }
          } else {
            if (cwind >= currentssthreshold) // congestion avoidance
              cwind = cwind + 1460/ cwind;
            else {
              cwind += 1460; // cwind = cwind + 1MSS
            }
            cWindList.add(cwind);
          }

        }
      }
      System.out.println("=======TCP Flow for "+(Integer)keys.get(i)+"====");
      System.out.println("timeoutRetransimission ===="+timeoutRetransimission);
      System.out.println("tripleAckRetransimission ===="+tripleAckRetransimission);
      int count = 0;
      for (int m=0;m<cWindList.size();m++) {
        if (count <10) {
          System.out.println("Cwind size "+(m+1)+": "+cWindList.get(m));
          count++;
        }

      }
    }
  }


}
