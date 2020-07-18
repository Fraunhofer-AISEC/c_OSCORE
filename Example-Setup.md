

```svgbob
.---------------------.                        .------------------.                        .------------------.
|                     |------------------------|                  |------------------------|                  |
|                     | unencrypted plain CoAP |                  | unencrypted plain CoAP |                  |
|   embedded device   |------------------------|  Raspberry Pi 1  |------------------------|  Raspberry Pi 2  |
|                     |                        |      (RPi1)      |                        |      (RPi2)      |
|     CoAP Server     |------------------------|   CoAP Gateway   |------------------------|   CoAP Client    |
|                     |    encrypted OSCORE    |                  |    encrypted OSCORE    |                  |
|                     |------------------------|                  |------------------------|                  |
'---------------------'                        '------------------'                        '------------------'  

                       \__________ ___________/                    \__________ ___________/      
                                  v                                           v
                   IpV6 over 6LoWPAN over Bluetooth                     IPv4 over LAN
```

Our Hardware / Operating System
* embedded device:
    * nRF52-PCA10040 (Nordic Semiconductor)
    * zephyr
* RPi1:
    * Raspberry Pi 3 Model B+
    * arch linux
* RPi2:
    * Rasperry Pi 3 Model B V1.2
    * arch linux
    
## Setup

Instead of arch-linux, feel free to use a different OS.
However, this guide is written completely based on arch-linux, so you may need to make according adjustments.

### RPi1 (Gateway):

* install arch:
    * follow "Installation" on https://archlinuxarm.org/platforms/armv8/broadcom/raspberry-pi-3
        * beware to execute most commands with sudo (for example bsdtar needs sudo)
    * do a system upgrade with `pacman -Syu`
        * use `su` on the RPi as sudo isn't installed on the base arch rpi image
    * edit the `/ect/sudoers` file and uncomment the `# %wheel` line to give the `alarm` user sudo permissions
    * install an AUR manager, like pikaur as described in <https://github.com/oberien/dotfiles/blob/a3d8debd445eaf992b770884d245fbd184b1cb4d/arch-install#L156-L162>
* setup bluetooth:
    * `sudo pacman -S sudo base-devel bluez bluez-utils`
    * `pikaur -S pi-bluetooth`
        * possibly skip the PGP check if the pgp key isn't imported
    * `systemctl enable brcm43438.service bluetooth.service`
* load 6lowpan modules: `sudo nano /etc/modules-load.d/oscore.conf`
    * content:
    ```
    6lowpan
    bluetooth_6lowpan
    ```
* network configuration (static IP adress):
    * `sudo nano /etc/systemd/network/20-oscore.network`
    ```
    [Match]
    Name=eth0

    [Network]
    Address=10.201.4.1/24
    ```
* compile c_OSCORE
    * install these dependencies
        * `sudo pacman -S cmake dtc gperf python-yaml python-pyelftools`
        * install `arm-none-eabi-gcc` on the RPi by following the instructions on <https://github.com/vanbwodonk/gcc-arm-embedded-build-armhf> (tested on commit [8219275266e81ac9ab205ffb1d82db55f32d50fe](https://github.com/vanbwodonk/gcc-arm-embedded-build-armhf/tree/8219275266e81ac9ab205ffb1d82db55f32d50fe))
    * follow instructions for building c_OSCORE from its section on Building in the `README.md`
* flashing:
    * instal JLink for flashing:
        * `wget --post-data 'accept_license_agreement=accepted&non_emb_ctr=confirmed&submit=Download+software' https://www.segger.com/downloads/jlink/JLink_Linux_arm.tgz`
        * `tar xvf JLink_Linux_arm.tgz`
        * `rm JLink_Linux_arm.tgz`
        * `cd JLink_Linux_V646g_arm/`
        * `cat README.txt`
        * `sudo cp 99-jlink.rules /etc/udev/rules.d/`
        * `sudo reboot`
    * flash `c_OSCORE/build/zephyr/zephyr.hex`:
        * `JLinkExe -device nrf51822 -speed 1000 -if swd`
        ```
        connect 1
        w4 4001e504 2
        w4 4001e50c 1
        sleep 100
        r
        w4 4001e504 1
        loadfile ./nitrogen_blinky.hex
        r
        g
        ```
* establish network to embedded device:
    * open serial console
        * `stty -F /dev/ttyACM0 115200 && cat /dev/ttyACM0`
    * `echo 1 | sudo tee /sys/kernel/debug/bluetooth/6lowpan_enable`
    * Pair Bluetooth node:
        + `sudo bluetoothctl`
            - `power on`
            - `list`
            - `select <target>` (from `list`)
            - `agent on`
            - `scan on`
            - `pair <MAC>`
    * Connect 6lowpan over bluetooth
        + `echo "connect <MAC> 2" | sudo tee /sys/kernel/debug/bluetooth/6lowpan_control`


### RPi2 (Client):

* install arch as described for RPi1
* when setting the static IP, use `10.201.4.1/24`

### Network Setup:

* either setup port forwarding, or configure gateway as router
* port forwarding:
    * client UDP:1337 → client TCP:1337 → ssh-tunnel → gateway TCP:1337 → embedded device UDP:5683
    * on gateway: `socat tcp-listen:1337 'udp-connect:[2001:db8::1]:5683'`
    * on client: `ssh -L '1337:localhost:1337' pi`
    * on client: `socat udp-listen:1337 tcp-connect:localhost:1337`
* test connection:
    * californium.tools/cf-browser
        + Download repository
        + install openjdk8
        + install openjfx (`java-openjfx`)
            - not included in openjk
            - only available for openjdk8
        + cd into `cf-browser`
        + `mvn package`
        + run with `java -jar target/cf-browser-1.1.0-SNAPSHOT.jar`
        * Point to `coap://localhost:1337`
    * another way is to run the `etsi_coaptest.sh`, which is an official CoAP testsuite
    * to test oscore, run `contrib/oscore-plugtest/plugtest-client` of the aicoap repository
        * implementation of the OSCORE test suite
        * only some methods are implemented by c_OSCORE
        * may need modification of the common-contexts

### Troubleshooting

* Zephyr's default implementation for CoAP only supports options with values of size 12 or less.
  `etsi_coaptest.sh` sends the `Uri-Host` option if the host is not a raw IPv6 address.
  Thus, if the IPv6 contains an interface, that option is set.
  Therefore, if e.g. `fe80::aaaa:bbbb:cccc:dddd%bt0` is used, zephyr will return an error and ignore the message, because it doesn't fit the `coap_option`'s value field of 12 bytes.
