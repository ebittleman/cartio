# CARTIO
[![GoDoc](https://godoc.org/github.com/ebittleman/cartio?status.svg)](https://godoc.org/github.com/ebittleman/cartio)

An e-commerce API.

## API

### CreateCart

#### Request
```json
{
    "command": "create_cart"
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "create_cart",
    "create_cart": {
        "cart_id": "<cart_id>"
    }
}
```

### AddItems

#### Request
```json
{
    "command": "add_items",
    "add_items": {
        "cart_id": "<cart_id>",
        "items": [
            {
                "product_id": "<product_id>",
                "qty": <unsigned int>
            },
            ...
        ]
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "add_items",
    "add_items": {
        "cart_id": "<cart_id>"
    }
}
```

### UpdateItems

#### Request
```json
{
    "command": "update_items",
    "update_items": {
        "cart_id": "<cart_id>",
        "items": [
            {
                "product_id": "<product_id>",
                "qty": <unsigned int>
            },
            ...
        ]
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "update_items",
    "update_items": {
        "cart_id": "<cart_id>"
    }
}
```

### RemoveItems

#### Request
```json
{
    "command": "remove_items",
    "remove_items": {
        "cart_id": "<cart_id>",
        "items": [
            {
                "product_id": "<product_id>"
            },
            ...
        ]
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "remove_items",
    "remove_items": {
        "cart_id": "<cart_id>"
    }
}
```

### AddCouponCode

#### Request
```json
{
    "command": "add_coupon_code",
    "add_coupon_code": {
        "cart_id": "<cart_id>",
        "coupon": "<coupon_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "add_coupon_code",
    "add_coupon_code": {
        "cart_id": "<cart_id>"
    }
}
```

### RemoveCouponCode

#### Request
```json
{
    "command": "remove_coupon_code",
    "remove_coupon_code": {
        "cart_id": "<cart_id>",
        "coupon": "<coupon_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "remove_coupon_code",
    "remove_coupon_code": {
        "cart_id": "<cart_id>"
    }
}
```

### SetSpecialInstructions

#### Request
```json
{
    "command": "set_special_instructions",
    "set_special_instructions": {
        "cart_id": "<cart_id>",
        "instructions": "<instructions>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "set_special_instructions",
    "set_special_instructions": {
        "cart_id": "<cart_id>"
    }
}
```

### CalculateShipping

#### Request
```json
{
    "command": "calculate_shipping",
    "calculate_shipping": {
        "cart_id": "<cart_id>",
        "postal_code": "<postal_code>",
        "country_code": "<country_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "calculate_shipping",
    "calculate_shipping": {
        "cart_id": "<cart_id>"
    }
}
```

### CalculateSalesTax

#### Request
```json
{
    "command": "calculate_sales_tax",
    "calculate_sales_tax": {
        "cart_id": "<cart_id>",
        "postal_code": "<postal_code>",
        "country_code": "<country_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "calculate_sales_tax",
    "calculate_sales_tax": {
        "cart_id": "<cart_id>"
    }
}
```

### SetShippingAddress

#### Request
```json
{
    "command": "set_shipping_address",
    "set_shipping_address": {
        "cart_id": "<cart_id>",
        "ship_to": "<ship_to>",
        "addr_1": "<Addr1>",
        "addr_2": "<Addr2>",
        "apt_suite": "<AptSuite>",
        "city": "<City>",
        "postal_code": "<postal_code>",
        "country_code": "<country_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "set_shipping_address",
    "set_shipping_address": {
        "cart_id": "<cart_id>"
    }
}
```

### SetBillingAddress

#### Request
```json
{
    "command": "set_billing_address",
    "set_billing_address": {
        "cart_id": "<cart_id>",
        "bill_to": "<bill_to>",
        "addr_1": "<Addr1>",
        "addr_2": "<Addr2>",
        "apt_suite": "<AptSuite>",
        "city": "<City>",
        "postal_code": "<postal_code>",
        "country_code": "<country_code>"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "set_billing_address",
    "set_billing_address": {
        "cart_id": "<cart_id>"
    }
}
```

### SetPaymentMethod

#### Request
```json
{
    "command": "set_payment_method",
    "set_billing_address": {
        "cart_id": "<cart_id>",
        "type": "< paypal | stripe | account_balance >"
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "set_payment_method",
    "set_payment_method": {
        "cart_id": "<cart_id>"
    }
}
```

### SubmitOrder

#### Request
```json
{
    "command": "submit_order",
    "submit_order": {
        "cart_id": "<cart_id>",
        "agree_to_terms": < true | false >,
        "timestamp": <unixtimestamp>
    }
}
```

#### Response
```json
{
    "request_id": "<request_id>",
    "command": "submit_order",
    "submit_order": {
        "cart_id": "<cart_id>"
    }
}
```

Copyright (C) 2017 Eric Bittleman
