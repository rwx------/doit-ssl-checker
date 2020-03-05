package main

import (
	"crypto/tls"
	"fmt"
	"os"

	"github.com/urfave/cli"
)

func main() {

	app := cli.NewApp()
	app.Name = "doit-ssl-checker"
	app.Usage = " 检测对应域名的ssl工具"
	app.Author = "yongfu"
	app.Description = "检查主机的https证书配置"
	app.ArgsUsage = "\n  ./doit-ssl-checker <-d domainname> [-i ip] [-p port] [-l]"

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "domain, d",
			Value: "www.liaoyongfu.com",
			Usage: "域名",
		},
		cli.StringFlag{
			Name:  "ip, i",
			Value: "",
			Usage: "可选：指定的ip，默认为空",
		},
		cli.StringFlag{
			Name:  "port, p",
			Value: "443",
			Usage: "可选：指定端口",
		},
		cli.BoolFlag{
			Name:  "long, l",
			Usage: "可选：是否输出全链路证书，默认不输出",
		},
	}

	app.Action = func(c *cli.Context) error {
		domain := c.String("domain")
		ip := c.String("ip")
		port := c.String("port")
		verbose := c.Bool("long")

		var addr string
		var cnf tls.Config

		if ip == "" {
			addr = domain + ":" + port
		} else {
			cnf.ServerName = domain
			addr = ip + ":" + port
		}

		conn, err := tls.Dial("tcp", addr, &cnf)
		if err != nil {
			fmt.Printf("[error]: %v", err.Error())
			//log.Fatalln(err.Error())
		}
		defer conn.Close()
		Dprint(conn, domain, verbose)
		return nil
	}
	app.Run(os.Args)
}

// Dprint doit检测工具的输出
func Dprint(conn *tls.Conn, domain string, verbose bool) {
	fmt.Printf("\n检测的域名: %v, 远程主机的ip: %v\n\n", domain, conn.RemoteAddr())
	status := conn.ConnectionState()

	if !verbose {
		key := status.PeerCertificates[0]
		fmt.Printf("Issuer.CommonName: %#v\n", key.Issuer.String())
		fmt.Printf("Subject: %#v\n", key.Subject.String())
		fmt.Printf("DNSNames: %v\n", key.DNSNames)
		fmt.Printf("NotBefor: %v\n", key.NotBefore.Format("2006-01-02 15:04:05"))
		fmt.Printf("NotAfter: %v\n", key.NotAfter.Format("2006-01-02 15:04:05"))
	} else {
		for i, v := range status.PeerCertificates {
			fmt.Printf("证书链: %v\n", i)
			fmt.Printf("Issuer.CommonName: %#v\n", v.Issuer.String())
			fmt.Printf("Subject: %#v\n", v.Subject.String())
			fmt.Printf("DNSNames: %v\n", v.DNSNames)
			fmt.Printf("NotBefor: %v\n", v.NotBefore.Format("2006-01-02 15:04:05"))
			fmt.Printf("NotAfter: %v\n", v.NotAfter.Format("2006-01-02 15:04:05"))
		}

		for i, v := range status.VerifiedChains {
			for j, k := range v {
				fmt.Printf("\ni: %v, j: %#v\n", i, j)
				fmt.Printf("Issuer: %#v\n", k.Issuer.String())
				fmt.Printf("Subject: %#v\n", k.Subject.String())
				fmt.Printf("NotBefore: %#v\n", k.NotBefore.Format("2006-01-02 15:04:05"))
				fmt.Printf("NotAfter: %#v\n\n", k.NotAfter.Format("2006-01-02 15:04:05"))
			}
		}
	}

}
