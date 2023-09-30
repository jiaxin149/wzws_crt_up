package main

import (
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

func Test_wzws(t *testing.T) {
	var wzws = "https://user.skyeye.qianxin.com/360oauth_redirect?state=http%3A%2F%2Fwangzhan.qianxin.com%2Flogin%2Flogin&code=448807115016a113b59704148ae42c450ec232127ddac833a"
	client := &http.Client{}
	req, err := http.NewRequest("GET", wzws, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 Edg/115.0.1901.188")
	if err != nil {
		fmt.Println("错误 ", err.Error())
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("错误 ", err.Error())
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Fatal error ", err.Error())
	}
	fmt.Println(string(content))
	for k, v := range resp.Header {
		fmt.Printf("%v, %v\n", k, v) // %v 打印响应头interfac{}的值
	}
	// 打印响应信息内容

	fmt.Printf("响应状态：%s,响应码： %d\n", resp.Status, resp.StatusCode)
	fmt.Printf("协议：%s\n", resp.Proto)
	fmt.Printf("响应内容长度： %d\n", resp.ContentLength)
	fmt.Printf("编码格式：%v\n", resp.TransferEncoding) // 未指定时为空
	fmt.Printf("是否压缩：%t\n", resp.Uncompressed)
	fmt.Printf("执行时间：%d\n", time.Now().Unix())
}
