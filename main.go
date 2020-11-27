package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/jessevdk/go-flags"
	"github.com/pkg/errors"
)

const (
	urlV4                 = "https://api.ipify.org"
	nexusMagicDescription = "### DO NOT EDIT THIS ### -- Nexus automatically updates this entry"
)

var opts struct {
	SecurityGroupID string `short:"s" long:"security-group-id" required:"true" description:"ID of security group."`
	LogFilePath     string `short:"l" long:"log-file-path" description:"Path of log file. Uses standard error, if not specified."`
	AWSProfile      string `long:"profile" required:"true" description:"AWS profile name"`
	AWSRegion       string `long:"region" required:"true" description:"AWS region name"`
	FromPort        int64  `short:"f" long:"from-port" description:"The start of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 type number. A value of -1 indicates all ICMP/ICMPv6 types. If you specify all ICMP/ICMPv6 types, you must specify all codes."`
	ToPort          int64  `short:"t" long:"to-port" description:" The end of port range for the TCP and UDP protocols, or an ICMP/ICMPv6 code. A value of -1 indicates all ICMP/ICMPv6 codes. If you specify all ICMP/ICMPv6 types, you must specify all codes."`
	IPProtocol      string `short:"p" long:"protocol" description:"The IP protocol name (tcp, udp, icmp, icmpv6) or number (see Protocol Numbers (http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)).\n[VPC only] Use -1 to specify all protocols. When authorizing security group rules, specifying -1 or a protocol number other than tcp, udp, icmp, or icmpv6 allows traffic on all ports, regardless of any port range you specify. For tcp, udp, and icmp, you must specify a port range. For icmpv6, the port range is optional; if you omit the port range, traffic for all types and codes is allowed."`
	Debug           bool   `short:"d" long:"debug" description:"output verbose messages for debugging."`
}

func main() {
	_, err := flags.Parse(&opts)
	if err != nil {
		log.Fatalf("error: unable to parse options: %+v\n", err)
	}

	for {
		err := update()
		if err != nil {
			logError(err)
		}
		sleep()
	}
}

func sleep() {
	logDebug("sleeping 1 minute ...")
	time.Sleep(1 * time.Minute)
}

func update() error {
	i4, err := getIPV4()
	if err != nil {
		return err
	}
	logDebug("my ipv4 == %s", i4)

	logDebug("getting security group info ...")
	sg, err := getSecurityGroup(opts.SecurityGroupID)
	if err != nil {
		return err
	}

	logDebug("check if need to update ...")
	if needToUpdate(i4, sg) {
		logDebug("trying to update ...")
		err = updateSecurityGroup(i4, sg)
		if err != nil {
			return err
		}
	}

	logDebug("done.")
	return nil
}

func getIPV4() (string, error) {
	b, err := httpGet(urlV4)
	return string(b), err
}

func createEC2Client() (*ec2.EC2, error) {
	s, err := session.NewSessionWithOptions(session.Options{
		Profile: opts.AWSProfile,
		Config: aws.Config{
			Region: aws.String(opts.AWSRegion),
		},
		SharedConfigState: session.SharedConfigEnable,
	})
	if err != nil {
		return nil, err
	}
	return ec2.New(s), nil
}

func getSecurityGroup(sgid string) (*ec2.SecurityGroup, error) {
	ec2Client, err := createEC2Client()
	if err != nil {
		return nil, err
	}
	in := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{&sgid},
	}
	out, err := ec2Client.DescribeSecurityGroups(in)
	if err != nil {
		return nil, err
	}
	if len(out.SecurityGroups) != 1 {
		return nil, errors.Errorf("found %d security groups. (expected 1)", len(out.SecurityGroups))
	}
	return out.SecurityGroups[0], nil
}

func needToUpdate(i4 string, sg *ec2.SecurityGroup) bool {
	if !allowedV4(i4, sg) {
		return true
	}
	return false
}

func allowedV4(i4 string, sg *ec2.SecurityGroup) bool {
	for _, perm := range sg.IpPermissions {
		for _, r := range perm.IpRanges {
			if isIPInSubnet(i4, *r.CidrIp) {
				return true
			}
		}
	}
	return false
}

func isIPInSubnet(ipStr, cidrStr string) bool {
	_, n, err := net.ParseCIDR(cidrStr)
	if err != nil {
		log.Printf("invalid CIDR: %s", cidrStr)
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		log.Printf("invalid IPv4: %s", ipStr)
		return false
	}

	return n.Contains(ip)
}

func updateSecurityGroup(i4 string, sg *ec2.SecurityGroup) error {
	ec2Client, err := createEC2Client()
	if err != nil {
		return err
	}

	err = revokeIPRangeWithNexusMagicDescriptionIfExist(ec2Client, sg)
	if err != nil {
		return err
	}

	logDebug("authorizing existing ip range ...")
	cidrIPv4 := i4 + "/32"
	in := &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: sg.GroupId,
		IpPermissions: []*ec2.IpPermission{
			{
				FromPort:   aws.Int64(opts.FromPort),
				ToPort:     aws.Int64(opts.ToPort),
				IpProtocol: aws.String(opts.IPProtocol),
				IpRanges: []*ec2.IpRange{
					{
						CidrIp:      aws.String(cidrIPv4),
						Description: aws.String(nexusMagicDescription),
					},
				},
			},
		},
	}
	_, err = ec2Client.AuthorizeSecurityGroupIngress(in)
	if err != nil {
		return err
	}
	return nil
}

func revokeIPRangeWithNexusMagicDescriptionIfExist(ec2Client *ec2.EC2, sg *ec2.SecurityGroup) error {
	for _, perm := range sg.IpPermissions {
		for _, r := range perm.IpRanges {
			if r.Description != nil && *r.Description == nexusMagicDescription {
				logDebug("revoking existing ip range ...")
				in := &ec2.RevokeSecurityGroupIngressInput{
					GroupId:    sg.GroupId,
					CidrIp:     r.CidrIp,
					FromPort:   perm.FromPort,
					ToPort:     perm.ToPort,
					IpProtocol: perm.IpProtocol,
				}
				_, err := ec2Client.RevokeSecurityGroupIngress(in)
				if err != nil {
					return err
				}
				return nil
			}
		}
	}

	return nil
}

func httpGet(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}

func logDebug(format string, s ...interface{}) {
	if !opts.Debug {
		return
	}

	msg := fmt.Sprintf(format, s...)
	if opts.LogFilePath == "" {
		log.Printf("debug: %s\n", msg)
		return
	}

	writeToLogFile(msg)
}

func logError(e error) {
	if opts.LogFilePath == "" {
		log.Printf("error: %+v\n", e)
		return
	}

	writeToLogFile(fmt.Sprintf("%+v\n", e))
}

func writeToLogFile(s string) {
	now := time.Now()
	timestamp := now.Format("2006/01/02 15:04:05")
	err := ioutil.WriteFile(opts.LogFilePath, []byte(timestamp+" "+s), 0644)
	if err != nil {
		log.Printf("error while writing to log file: %+v\n", err)
		log.Printf("%s\n", s)
	}
}
