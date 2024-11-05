package tls

import (
	"io"
)

type HeadTransferLayer struct {
	layer *ITransferLayer
}

type EndTransferLayer struct {
	layer *ITransferLayer
	io.ReadWriter
}

type ITransferLayer interface {
	Next() ITransferLayer
	SetNext(next ITransferLayer)
	Last() ITransferLayer
	SetLast(last ITransferLayer)
	WriteToNext(p []byte) (int, error)
	ReadFromNextUtil() ([]byte, error)
}
