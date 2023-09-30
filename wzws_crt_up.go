package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"time"
)

var (
	Q         = ""
	T         = ""
	Domain    = ""
	phpsessid = ""
	phptime   = 0

	hostArray = []string{}
)

type Conf struct {
	T         string `json:"T"`
	Q         string `json:"Q"`
	Domain    string `json:"domain"`
	Phpsessid string `json:"phpsessid"`
	Phptime   int    `json:"phptime"`
}
type Domain_And_Host_list struct {
	Status string `json:"status"`
	Res    struct {
		List []struct {
			Domain string `json:"domain"`
			Host   string `json:"host"`
		} `json:"list"`
	} `json:"res"`
}

func main() {
	fmt.Println("当前时间戳：", time_new())
	read_conf() //读取配置文件
	if Q == "" && T == "" && Domain == "" {
		fmt.Println("配置参数为空，请补充配置文件")
	} else if phpsessid == "" && phptime == 0 {
		fmt.Println("php参数数据为空")
		login360() //使用360cookie登录
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("本次操作的子域名是：", item)
			time.Sleep(1 * time.Second)
		}
		//up_crt("www", "jaxing.cc")
	} else if phptime < int(time_new()) {
		fmt.Println("phpsessid过期")
		login360() //使用360cookie登录
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("上传的证书域名是：", item)
			time.Sleep(1 * time.Second)
		}
		//getHostList("jaxing.cc") //获取子域列表
		//up_crt("www", "jaxing.cc")
	} else if phpsessid != "" && phptime > int(time_new()) {
		fmt.Println("时间戳未过期，直接登录")
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("上传的证书域名是：", item)
			time.Sleep(1 * time.Second)
		}
		write_conf()
	} else {
		fmt.Println("读取配置文件参数时错误")
	}
	time.Sleep(2 * time.Second)
}

// 获取当前时间戳
func time_new() int64 {
	time_new := time.Now().Unix()
	return time_new
}

// 获取过期时间戳
func time_30() int64 {
	return time.Now().Add(30 * time.Minute).Unix()
}

// 上传证书
func up_crt(host_str string, domain_str string) {
	if get_file_time("fullchain.pem") < time_new()-(5*24*60*60) {
		fmt.Println("证书文件时间更新大于五天以上，暂不用上传")
		return
	}
	var requestBody bytes.Buffer
	// 创建一个 multipart writer，将内容写入缓冲区
	multipartWriter := multipart.NewWriter(&requestBody)
	// 添加文本字段
	domain, err := multipartWriter.CreateFormField("domain")
	if err != nil {
		fmt.Println("创建文本字段错误:", err)
		return
	}
	domain.Write([]byte(domain_str))
	host, err := multipartWriter.CreateFormField("host")
	if err != nil {
		fmt.Println("创建文本字段错误:", err)
		return
	}
	host.Write([]byte(host_str))
	// 添加文件字段
	crt, err := multipartWriter.CreateFormFile("ssl_cert", "fullchain.crt")
	if err != nil {
		fmt.Println("创建文件字段crt错误:", err)
		return
	}

	// 打开并读取文件内容
	file, err := os.Open("fullchain.pem")
	if err != nil {
		fmt.Println("打开文件crt错误:", err)
		return
	}
	defer file.Close()

	// 将文件内容复制到文件字段中
	_, err = io.Copy(crt, file)
	if err != nil {
		fmt.Println("复制文件crt内容错误:", err)
		return
	}
	key, err := multipartWriter.CreateFormFile("ssl_key", "privkey.key")
	if err != nil {
		fmt.Println("创建文件key错误:", err)
		return
	}

	// 打开并读取文件2的内容
	file2, err := os.Open("privkey.pem")
	if err != nil {
		fmt.Println("打开文件key错误:", err)
		return
	}
	_, err = io.Copy(key, file2)
	if err != nil {
		fmt.Println("复制文件key内容错误:", err)
		return
	}
	// 完成 multipart 请求
	multipartWriter.Close()

	// 创建 POST 请求
	req, err := http.NewRequest("POST", "https://wangzhan.qianxin.com/protect/addcert", &requestBody)
	if err != nil {
		fmt.Println("创建请求错误:", err)
		return
	}

	// 设置请求头，指定 multipart/form-data 类型
	req.Header.Set("Content-Type", multipartWriter.FormDataContentType())
	req.Header.Set("Cookie", "PHPSESSID="+phpsessid)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188")
	req.Header.Set("Referer", "https://wangzhan.qianxin.com")
	// 发送请求
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("证书上传发送请求错误:", err)
		return
	}
	defer resp.Body.Close()
	body, _ := (io.ReadAll(resp.Body))
	html := string(body)

	// 处理响应
	fmt.Println("证书上传响应状态码:", resp.Status)
	fmt.Println("证书上传响应内容:", html)
}

// 判断go_conf.json配置文件是否存在并读取配置文件
func read_conf() {
	filename := "go_conf.json"
	_, err := os.Stat(filename)
	if os.IsNotExist(err) {
		fmt.Println("配置文件不存在")
		data := map[string]interface{}{
			"//提示":      "下方T、Q的值请填写360登录的cookie里对应的T、Q值,domain填写你的域名，剩下的phpsessid和phptime请忽略,这两个由程序自动生成读写",
			"T":         "",
			"Q":         "",
			"domain":    "",
			"phpsessid": "",
			"phptime":   0,
		}

		jsonData, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			fmt.Println("JSON编码失败:", err)
			return
		}

		err = os.WriteFile("go_conf.json", jsonData, 0644)
		if err != nil {
			fmt.Println("写入配置文件失败：", err)
			return
		}

		fmt.Println("配置文件已创建并成功写入基础数据,请在该程序目录下查看名为【go_conf.json的文件】并补充完数据后再重新运行")
		os.Exit(0)
	} else if err == nil {
		file, err := os.ReadFile(filename)
		if err != nil {
			fmt.Println("读取文件时出现错误：", err)
			return
		}
		var config Conf
		err = json.Unmarshal(file, &config)
		if err != nil {
			fmt.Println("解析JSON时出现错误: ", err)
			return
		}
		//赋值变量
		Q = config.Q
		T = config.T
		Domain = config.Domain
		phpsessid = config.Phpsessid
		phptime = config.Phptime
	} else {
		fmt.Println("配置文件存在")
	}
}

// 写入配置文件
func write_conf() {
	data := map[string]interface{}{
		"//提示":      "下方T、Q的值请填写360登录的cookie里对应的T、Q值,剩下的phpsessid和phptime请忽略,这两个由程序自动生成读写",
		"T":         T,
		"Q":         Q,
		"Domain":    Domain,
		"phpsessid": phpsessid,
		"phptime":   int(time_30()),
	}

	jsonData, err := json.MarshalIndent(data, "", "    ")
	if err != nil {
		fmt.Println("JSON编码失败:", err)
		return
	}

	err = os.WriteFile("go_conf.json", jsonData, 0644)
	if err != nil {
		fmt.Println("写入配置文件失败：", err)
		return
	}

	fmt.Println("配置更新写入完成")
}

// 获取证书文件的修改时间
func get_file_time(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		log.Println("打开证书文件失败", err)
		return time.Now().Unix()
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		log.Println("stat文件信息错误")
		return time.Now().Unix()
	}
	return fi.ModTime().Unix()
}

// 使用360cookie登录
func login360() {
	fmt.Println("使用360登录")
	jar, _ := cookiejar.New(nil)
	session := &http.Client{Jar: jar}
	// 创建http请求
	url := "https://openapi.360.cn/oauth2/authorize"
	data := "client_id=02f55d8f4dd80ac05e0a16617df49e26&response_type=code&redirect_uri=https%3A%2F%2Fuser.skyeye.qianxin.com%2F360oauth_redirect&state=http%3A%2F%2Fwangzhan.qianxin.com%2Flogin%2Flogin&scope=&display=default&mid=&version=&DChannel="
	http, _ := http.NewRequest("POST", url, strings.NewReader(data))
	http.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	http.Header.Set("Cookie", "Q="+Q+"; T="+T)
	http.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188")
	// 发送http请求
	res, err := session.Do(http)
	if err != nil {
		fmt.Println("http错误:", err)
		return
	}
	// 读取响应内容
	defer res.Body.Close()
	body, _ := (io.ReadAll(res.Body))
	html := string(body)
	if strings.Contains(html, "用户唯一标识：") {
		fmt.Println("网站卫士登录成功")
		cookies := session.Jar.Cookies(res.Request.URL)
		for _, cookie := range cookies {
			if cookie.Name == "PHPSESSID" {
				fmt.Println("获取到的PHPSESSID:", cookie.Value)
				phpsessid = cookie.Value
				break
			}
		}
		write_conf()
	} else if strings.Contains(html, "您正在访问的应用暂时无法正常提供服务") {
		fmt.Println("360Cooke可能已经失效，请更新cookie再次尝试")
	}else if strings.Contains(html, "什么都没有发现啊") {
		fmt.Println("360或奇安信响应过忙，等下重试看看")
	}else {
		fmt.Println("网站卫士登录失败")
		phpsessid = ""
	}

}

// 获取域名列表
// func getDomainList() {
// 	if_phpsessid()
// 	cli := &http.Client{}
// 	url := "https://wangzhan.qianxin.com/domain/getDomainList"
// 	data := "start=0"
// 	http, _ := http.NewRequest("POST", url, strings.NewReader(data))
// 	http.Header.Set("Content-type", "application/x-www-form-urlencoded;charset=UTF-8")
// 	http.Header.Set("Cookie", "PHPSESSID="+phpsessid)
// 	res, err := cli.Do(http)
// 	if err != nil {
// 		fmt.Println("错误:", err)
// 	}
// 	defer res.Body.Close()
// 	body, _ := (io.ReadAll(res.Body))
// 	var domainlist Domain_And_Host_list
// 	if err := json.Unmarshal(body, &domainlist); err != nil {
// 		panic(err)
// 	}

// 	for _, item := range domainlist.Res.List {
// 		fmt.Println("域名列表：", item.Domain)
// 		domainArray = append(domainArray, item.Domain)
// 	}

// }

// 获取子域列表
func getHostList(domain string) {
	if_phpsessid()
	cli := &http.Client{}
	url := "https://wangzhan.qianxin.com/dns/getHostList"
	data := "start=0&domain=" + domain
	http, _ := http.NewRequest("POST", url, strings.NewReader(data))
	http.Header.Set("Content-type", "application/x-www-form-urlencoded;charset=UTF-8")
	http.Header.Set("Cookie", "PHPSESSID="+phpsessid)
	res, err := cli.Do(http)
	if err != nil {
		fmt.Println("http错误:", err)
	}
	defer res.Body.Close()
	body, _ := (io.ReadAll(res.Body))

	var hostlist Domain_And_Host_list
	if err := json.Unmarshal(body, &hostlist); err != nil {
		fmt.Println(err)
	}
	if hostlist.Status != "ok" {
		fmt.Println("奇安信返回验证数据错误返回错误json，请检查参数")
		fmt.Println("奇安信返回的JSON ：", string(body))
		return
	}
	for _, item := range hostlist.Res.List {
		fmt.Println("子域列表：", item.Host)
		hostArray = append(hostArray, item.Host)
	}

}

// 验证phpsessid格式
func if_phpsessid() {
	if len(phpsessid) == 32 && phpsessid != "" {
		fmt.Println("phpsessid验证成功")
	} else {
		fmt.Println("phpsessid验证失败,已停止运行")
		os.Exit(0)
	}

}
