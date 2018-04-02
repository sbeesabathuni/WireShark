/**
 * Created by parallels on 3/2/18.
 */
public class TCPDataPacket {
  private int sourcePort;
  private int destPort;
  private long seqNumber;
  private long ackNumber;
  private int flag;
  private int window;
  private int checkSum;
  private int urgent;
  private long options;
  private long data;
  private double timeStamp;
  private double packetLength;
  private int dataOffset;
  private byte[] payload;
  private String parsedHTTPHeader;


  public double getTimeStamp() {
    return timeStamp;
  }

  public void setTimeStamp(double timeStamp) {
    this.timeStamp = timeStamp;
  }

  public int getSourcePort() {
    return sourcePort;
  }

  public void setSourcePort(int sourcePort) {
    this.sourcePort = sourcePort;
  }

  public int getDestPort() {
    return destPort;
  }

  public void setDestPort(int destPort) {
    this.destPort = destPort;
  }

  public long getSeqNumber() {
    return seqNumber;
  }

  public void setSeqNumber(long seqNumber) {
    this.seqNumber = seqNumber;
  }

  public long getAckNumber() {
    return ackNumber;
  }

  public void setAckNumber(long ackNumber) {
    this.ackNumber = ackNumber;
  }

  public int getFlag() {
    return flag;
  }

  public void setFlag(int flag) {
    this.flag = flag;
  }

  public int getWindow() {
    return window;
  }

  public void setWindow(int window) {
    this.window = window;
  }

  public int getCheckSum() {
    return checkSum;
  }

  public void setCheckSum(int checkSum) {
    this.checkSum = checkSum;
  }

  public int getUrgent() {
    return urgent;
  }

  public void setUrgent(int urgent) {
    this.urgent = urgent;
  }

  public long getOptions() {
    return options;
  }

  public void setOptions(long options) {
    this.options = options;
  }

  public long getData() {
    return data;
  }

  public void setData(long data) {
    this.data = data;
  }

  public double getPacketLength() {
    return packetLength;
  }

  public void setPacketLength(double packetLength) {
    this.packetLength = packetLength;
  }

  public int getDataOffset() {
    return dataOffset;
  }

  public void setDataOffset(int dataOffset) {
    this.dataOffset = dataOffset;
  }

  public byte[] getPayload() {
    return payload;
  }

  public void setPayload(byte[] payload) {
    this.payload = payload;
  }

  public String getParsedHTTPHeader() {
    return parsedHTTPHeader;
  }

  public void setParsedHTTPHeader(String parsedHTTPHeader) {
    this.parsedHTTPHeader = parsedHTTPHeader;
  }
}
