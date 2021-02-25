/*
Copyright 2017, 2019 the Velero contributors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/runtime"

	v1 "github.com/vmware-tanzu/velero/pkg/apis/velero/v1"
	"github.com/vmware-tanzu/velero/pkg/plugin/velero"
)

type BackupPlugin struct {
	log    logrus.FieldLogger
	secret string
}

func NewBackupPlugin(log logrus.FieldLogger) *BackupPlugin {
	secret, _ := getSecret()
	return &BackupPlugin{log: log, secret: secret}
}

func (p *BackupPlugin) AppliesTo() (velero.ResourceSelector, error) {
	return velero.ResourceSelector{}, nil
}

func (p *BackupPlugin) Execute(item runtime.Unstructured, backup *v1.Backup) (runtime.Unstructured, []velero.ResourceIdentifier, error) {
	p.log.Info("encrypting item")

	// change everything to map in format({"encrypted": encrypted json string})
	content := item.UnstructuredContent()
	serialized, err := json.Marshal(content)
	if err != nil {
		p.log.Error(fmt.Sprintf("failed to serialize item %v ", err))
		return nil, nil, err
	}

	encrypted := encrypt(string(serialized), p.secret)
	m := make(map[string]interface{})
	m["content"] = encrypted
	m["kind"] = content["kind"]
	item.SetUnstructuredContent(m)
	p.log.Info(item)
	p.log.Info("encrypted item")
	return item, nil, nil
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {

	key, _ := hex.DecodeString(keyString)
	plaintext := []byte(stringToEncrypt)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return fmt.Sprintf("%x", ciphertext)
}
