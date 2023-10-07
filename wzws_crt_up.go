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
	"strconv"
	"strings"
	"time"

	"github.com/robfig/cron"
)

var (
	Q         = ""
	T         = ""
	Domain    = ""
	phpsessid = ""
	phptime   = 0

	hostArray = []string{}

	push_text string = ""
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
type Get_visitbase_data_json struct {
	Status string `json:"status"`
	Res    struct {
		Basedata struct {
			Pv            int `json:"pv"`
			IP            int `json:"ip"`
			Uv            int `json:"uv"`
			Visit         int `json:"visit"`
			Cachehit      int `json:"cachehit"`
			Cacheband     float64 `json:"cacheband"`
			Totalband     float64 `json:"totalband"`
			Takehours     int `json:"takehours"`
			Savehours     int `json:"savehours"`
			Searchbot     int `json:"searchbot"`
			Searchfrom    int `json:"searchfrom"`
			Err403        int `json:"err403"`
			Err404        int `json:"err404"`
			Err500        int `json:"err500"`
			Err502        int `json:"err502"`
			MaxBand       string    `json:"maxBand"`
			ResourceVisit int   `json:"resource_visit"`
			ToBackFlow    float64   `json:"to_back_flow"`
			Err403P       string    `json:"err403p"`
			Err404P       string    `json:"err404p"`
			Err500P       string    `json:"err500p"`
			Err502P       string    `json:"err502p"`
		} `json:"basedata"`
		Visitfrom struct {
			VisitCount float64 `json:"visit_count"`
			PvCount    float64 `json:"pv_count"`
			UvCount    float64 `json:"uv_count"`
			IPCount    float64 `json:"ip_count"`
		} `json:"visitfrom"`
	} `json:"res"`
}
type Get_safebase_data struct {
	Status string `json:"status"`
	Res    struct {
		Visit      int `json:"visit"`
		Webcount   int `json:"webcount"`
		Cccount    int `json:"cccount"`
		Totalcount int `json:"totalcount"`
		Days       int `json:"days"`
	} `json:"res"`
}

func main() {
	c := cron.New()
	spec := "0 0 23 * * *"
	c.AddFunc(spec, func() {
		run()
	})
	c.Start()
	select {}
}
func run(){
	fmt.Println("当前时间戳：", time_new())
	read_conf() //读取配置文件
	push_text+="网站卫士证书更新程序运行状态通知\n"
	if Q == "" && T == "" && Domain == "" {
		fmt.Println("配置参数为空，请补充配置文件")
		push_text+="配置参数为空"
	} else if phpsessid == "" && phptime == 0 {
		fmt.Println("php参数数据为空")
		push_text+="php参数为空"
		login360() //使用360cookie登录
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("本次操作的子域名是：", item)
			time.Sleep(1 * time.Second)
			fmt.Println(get_visitbase_data(Domain, item))
			fmt.Println(get_safebase_data(Domain, item))
			push_text+=get_visitbase_data(Domain, item)
			push_text+="#############"
			push_text+=get_safebase_data(Domain, item)
			push_text+="#############"
		}
	} else if phptime < int(time_new()) {
		fmt.Println("phpsessid过期")
		push_text+="phpid过期"
		login360() //使用360cookie登录
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("上传的证书域名是：", item)
			time.Sleep(1 * time.Second)
			fmt.Println(get_visitbase_data(Domain, item))
			fmt.Println(get_safebase_data(Domain, item))
			push_text+=get_visitbase_data(Domain, item)
			push_text+="#############"
			push_text+=get_safebase_data(Domain, item)
			push_text+="#############"
		}
	} else if phpsessid != "" && phptime > int(time_new()) {
		fmt.Println("时间戳未过期，直接登录")
		push_text+="直接登录"
		getHostList(Domain)
		time.Sleep(1 * time.Second)
		for _, item := range hostArray {
			up_crt(item, Domain)
			fmt.Println("上传的证书域名是：", item)
			time.Sleep(1 * time.Second)
			fmt.Println(get_visitbase_data(Domain, item))
			fmt.Println(get_safebase_data(Domain, item))
			push_text+=get_visitbase_data(Domain, item)
			push_text+="#############"
			push_text+=get_safebase_data(Domain, item)
			push_text+="#############"
		}
		write_conf()
	} else {
		fmt.Println("读取配置文件参数时错误")
	}
	//push()
	time.Sleep(2 * time.Second)
}
//推送
// func push()  {
// 	token:="99058c58aca24958875fab762f8ef20a"
// 	url := "http://www.pushplus.plus/send?token="+token+"&content="+url.PathEscape(push_text)
// 	resp, err := http.Get(url)
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer resp.Body.Close()
// 	body, _ := (io.ReadAll(resp.Body))
// 	fmt.Println(string(body))
// }
// 流量转换方法
func convertBytes(size float64) string {
	var unit string
	if size < 1024 {
		unit = "B"
	} else if size < 1024*1024 {
		size /= 1024
		unit = "KB"
	} else if size < 1024*1024*1024 {
		size /= 1024 * 1024
		unit = "MB"
	} else if size < 1024*1024*1024*1024 {
		size /= 1024 * 1024 * 1024
		unit = "GB"
	} else {
		size /= 1024 * 1024 * 1024 * 1024
		unit = "TB"
	}
	return fmt.Sprintf("%.2f%s", size, unit)
}

// 获取流量报表
func get_visitbase_data(domain string, host string) string {
	if_phpsessid()
	post := http.Client{}
	url := "https://wangzhan.qianxin.com/report/get_visitbase_data"
	data := "domain=" + domain + "&host=" + host
	http, _ := http.NewRequest("POST", url, strings.NewReader(data))
	http.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	http.Header.Set("Cookie", "PHPSESSID="+phpsessid)
	res, err := post.Do(http)
	if err != nil {
		fmt.Println("http错误:", err)
		return "http错误" + err.Error()
	}
	// 读取响应内容
	defer res.Body.Close()
	body, _ := (io.ReadAll(res.Body))
	var json_str Get_visitbase_data_json
	if err := json.Unmarshal(body, &json_str); err != nil {
		fmt.Println(err)
	}
	if json_str.Status != "ok" {
		fmt.Println("奇安信返回验证数据错误返回错误json，请检查参数")
		fmt.Println("奇安信返回的JSON ：", string(body))
		return "奇安信返回验证数据错误返回错误json，请检查参数" + "奇安信返回的JSON ：" + string(body)
	}
	visit :=strconv.Itoa(json_str.Res.Basedata.Visit)  //总请求数
	pv :=strconv.Itoa( json_str.Res.Basedata.Pv  )     //页面访问量
	uv := strconv.Itoa(json_str.Res.Basedata.Uv  )     //独立访客数
	ip := strconv.Itoa(json_str.Res.Basedata.IP)       //独立访问ip数

	cachehit := strconv.Itoa(json_str.Res.Basedata.Cachehit)          //加速次数
	resource_visit := strconv.Itoa(json_str.Res.Basedata.ResourceVisit) //回源次数

	cacheband := json_str.Res.Basedata.Cacheband     //加速流量
	to_back_flow := json_str.Res.Basedata.ToBackFlow //回源流量
	totalband := json_str.Res.Basedata.Totalband     //总流量
	text := "\n网站访问报告: "+
		host+"."+domain+
		"\n总请求量"+
		visit+
		"\n页面访问量"+
		pv+
		"\n独立访问量"+
		uv+
		"\n独立ip量"+
		ip+
		"\n加速次数"+
		cachehit+
		"\n回源次数"+
		resource_visit+
		"\n加速流量"+
		convertBytes(cacheband)+
		"\n回源流量"+
		convertBytes(to_back_flow)+
		"\n总流量"+
		convertBytes(totalband)
	fmt.Println(text)
	return text
}

// 获取网站安全报表
func get_safebase_data(domain string, host string) string {
	if_phpsessid()
	post := http.Client{}
	url := "https://wangzhan.qianxin.com/report/get_safebase_data"
	data := "domain=" + domain + "&host=" + host
	http, _ := http.NewRequest("POST", url, strings.NewReader(data))
	http.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	http.Header.Set("Cookie", "PHPSESSID="+phpsessid)
	res, err := post.Do(http)
	if err != nil {
		fmt.Println("http错误:", err)
		return "http错误:" + err.Error()
	}
	defer res.Body.Close()
	body, _ := (io.ReadAll(res.Body))
	var json_str Get_safebase_data
	if err := json.Unmarshal(body, &json_str); err != nil {
		fmt.Println(err)
	}
	if json_str.Status != "ok" {
		fmt.Println("奇安信返回验证数据错误返回错误json，请检查参数")
		fmt.Println("奇安信返回的JSON ：", string(body))
		return "奇安信返回验证数据错误返回错误json，请检查参数" + "奇安信返回的JSON ：" + string(body)
	}

	visit := strconv.Itoa(json_str.Res.Visit)           //正常访问数
	webcount := strconv.Itoa(json_str.Res.Webcount)     //web攻击数
	cccount := strconv.Itoa(json_str.Res.Cccount)       //cc攻击数
	days := strconv.Itoa(json_str.Res.Days)             //已防护天数
	totalcount := strconv.Itoa(json_str.Res.Totalcount) //恶意攻击数

	text :=
		"\n网站安全报告: " +
			host + "." + domain +
			"\n已防护天数" +
			days +
			"\n正常访问数" +
			visit +
			"\nweb攻击数" +
			webcount +
			"\ncc攻击数" +
			cccount +
			"\n恶意攻击数" +
			totalcount
	fmt.Println(text)
	return text
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

	// 打开并读取文件的内容
	file2, err := os.Open("privkey.pem")
	if err != nil {
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
	} else if strings.Contains(html, "什么都没有发现啊") {
		fmt.Println("360或奇安信响应过忙，等下重试看看")
	} else {
		fmt.Println("网站卫士登录失败")
		phpsessid = ""
	}

}

//获取域名列表
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
