function stWlanWifi(domain,name,enable,ssid,mode,channel,power,Country,AutoChannelEnable,channelWidth)
{
this.ssid = ssid;
}
var WlanWifiArr = new Array(new stWlanWifi("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1","ath0","1","On\x2dsite\x20","11bgn","0","100","CN","1","0"),null);
WlanWifi = new stWlanWifi("","","","","11n","","","","","");
var WlanArr = new Array(new stWlan("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1","ath0","1","On\x2dsite\x20","1","32","1","WPAand11i","None","None","1","104\x2dbit","TKIPEncryption","PSKAuthentication","AESEncryption","PSKAuthentication","TKIPandAESEncryption","PSKAuthentication","3600","192\x2e168\x2e0\x2e100","1812","19550943","1"),null);
Wlan[i] = new stWlan();
var wpaPskKey = new Array(new stPreSharedKey("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2ePreSharedKey\x2e1","fixture\x2dwifi\x2dpassphrase",""),null);
var wpsPinNum = new Array(new stWpsPin("InternetGatewayDevice\x2eLANDevice\x2e1\x2eWLANConfiguration\x2e1\x2eWPS","PushButton","12345670","AP","0"),null);
