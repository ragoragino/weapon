#### Weapon 
Weapon is a simple VPN written in Rust.

#### Sources
https://www.reddit.com/r/golang/comments/nvzcyf/is_it_possible_to_write_a_working_vpn_service_in/
Mastering OpenVPN: Master building and integrating secure private networks using OpenVPN
https://community.openvpn.net/openvpn/wiki/BridgingAndRouting?__cf_chl_jschl_tk__=a3Nz8Iq8lfORY1pZ2ORJVvotU9y.GE1KuaQA1eeD.Rs-1641741448-0-gaNycGzNCH0
https://openvpn.net/vpn-server-resources/site-to-site-routing-explained-in-detail/


https://www.gabriel.urdhr.fr/2021/05/08/tuntap/
https://www.kernel.org/doc/Documentation/networking/tuntap.txt

Setting up docker networks:

``` 
// docker.json
{
  "default-address-pools":
  [
    {"base":"172.18.0.0/16","size":24}
  ]
}
```