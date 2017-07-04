package iface

import (
	"context"

	"github.com/ebittleman/cartio/domain/product"
)

type ProductService interface {
	GetProduct(context.Context, *product.GetProductInput) (*product.GetProductOutput, error)
}
