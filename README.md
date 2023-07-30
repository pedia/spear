# stupid_alipay

Most simply alipay SDK implement in Go

```go
pr, err := NewSpare("appid", "app_private_key", "app_public_key", "aeskey")
pr.Do("alipay.trade.page.pay", map[string]string{
    "subject":      "支付测试",
    "out_trade_no": "12312311",
    "total_amount": "10.00",
    "product_code": "FAST_INSTANT_TRADE_PAY",
})
```
