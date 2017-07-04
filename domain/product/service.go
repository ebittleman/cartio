package product

type GetProductInput struct {
	ProductID string
}

type GetProductOutput struct {
	Product Product
}
