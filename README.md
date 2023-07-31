# stupid_alipay

Most simply alipay SDK implement in Go

Example trade of a PC Web site
```go
pr, err := NewSpare("appid", "app_private_key", "app_public_key", "aeskey")
pr.Do("alipay.trade.page.pay", map[string]string{
    "subject":      "PRODUCT NAME",
    "out_trade_no": "001233734",
    "total_amount": "0.99",
    "product_code": "FAST_INSTANT_TRADE_PAY",
})
```
