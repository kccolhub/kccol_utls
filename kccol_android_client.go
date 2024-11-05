package tls

type KccolAndroidClient struct {
	//from Android VPNService
	fileDescriptor int
}

func NewKccolAndroidClient(fileDescriptor int) *KccolAndroidClient {
	return &KccolAndroidClient{
		fileDescriptor: fileDescriptor,
	}
}

func (k *KccolAndroidClient) Start() {

}

func (k *KccolAndroidClient) Stop() {

}
