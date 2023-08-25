//  Copyright (c) 2021-22, VMware Inc, and the Certifier Authors.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package certlib

import (
	"crypto/rand"
	"fmt"
	"google.golang.org/protobuf/proto"
	"io/ioutil"
	"os"

	certprotos "github.com/vmware-research/certifier-framework-for-confidential-computing/certifier_service/certprotos"
)

func PolicyStoreNumEntries(ps *certprotos.PolicyStoreMessage) int {
	return len(ps.Entries)
}

func PrintPolicyStoreEntry(e *certprotos.PolicyStoreEntry) {
	fmt.Printf("Tag: %s, Type: %s, Value: ", e.GetTag(), e.GetType())
	PrintBytes(e.GetValue())
	fmt.Printf("\n")
}

func NewPolicyStoreEntry(tag string, valueType string, value []byte) *certprotos.PolicyStoreEntry {
	e := new(certprotos.PolicyStoreEntry)
	e.Tag = &tag
	e.Type = &valueType
	e.Value = value
	return e
}

func NewPolicyStore(maxEnts int) *certprotos.PolicyStoreMessage {
	ps := new(certprotos.PolicyStoreMessage)
	me := int32(maxEnts)
	ps.MaxEnts = &me
	return ps
}

func PrintPolicyStore(ps *certprotos.PolicyStoreMessage) {
	fmt.Printf("Maximum Entries: %d, current entries: %d\n", int(ps.GetMaxEnts()), len(ps.Entries))
	for i := 0; i < len(ps.Entries); i++ {
		fmt.Printf("   ")
		PrintPolicyStoreEntry(ps.Entries[i])
	}
}

func FindPolicyStoreEntry(ps *certprotos.PolicyStoreMessage, tag string, valueType string) int {
	for i := 0; i < len(ps.Entries); i++ {
		if ps.Entries[i].GetTag() == tag && ps.Entries[i].GetType() == valueType {
			return i
		}
	}
	return -1
}

func InsertOrUpdatePolicyStoreEntry(ps *certprotos.PolicyStoreMessage, tag string, valueType string, value []byte) bool {
	ent := FindPolicyStoreEntry(ps, tag, valueType)
	if ent >= 0 {
		ps.Entries[ent].Value = value
		return true
	}
	if len(ps.Entries) >= int(ps.GetMaxEnts()) {
		return false
	}
	pse := NewPolicyStoreEntry(tag, valueType, value)
	ps.Entries = append(ps.Entries, pse)
	return true
}

func PolicyStoreDeleteEntry(ent int) {
}

func ConstructKeyForProtect(keyName string, keyType string) *certprotos.KeyMessage {

	// only alg for now is "aes-256-cbc-hmac-sha256"
	if keyType != "aes-256-cbc-hmac-sha256" {
		fmt.Printf("ConstructKeyForProtect: only aes-256-cbc-hmac-sha256 is supported\n")
		return nil
	}

	nakedKey := make([]byte, 64)
	_, err := rand.Read(nakedKey)
	if err != nil {
		fmt.Printf("ConstructKeyForProtect: Can't construct iv\n")
		return nil
	}

	k := new(certprotos.KeyMessage)

	tn := TimePointNow()
	if tn == nil {
		fmt.Printf("ConstructKeyForProtect: Can't get TimeNow\n")
		return nil
	}
	
	tf := TimePointPlus(tn, 365*86400)
	if tf == nil {
		fmt.Printf("ConstructKeyForProtect: Can't get TimeAfter\n")
		return nil
	}

	nb := TimePointToString(tn)
	na := TimePointToString(tf)

	k.KeyName = &keyName
	k.KeyType = &keyType
	format := "vse-key"
	k.KeyFormat = &format
	k.SecretKeyBits = nakedKey
	k.NotBefore = &nb
	k.NotAfter = &na
	return k
}

func ProtectBlob(enclaveType string, k *certprotos.KeyMessage, buffer []byte) []byte {

	if k.GetKeyType() != "aes-256-cbc-hmac-sha256" {
		fmt.Printf("ProtectBlob: Wrong key type for authenticated encrypt\n")
		return nil
	}

	pb := new(certprotos.ProtectedBlobMessage)
	if pb == nil {
		fmt.Printf("ProtectBlob: Can't new ProtectedBlobMessage\n")
		return nil
	}

	// iv for data	
	iv := make([]byte, 16)
	_, err := rand.Read(iv)
	if err != nil {
		fmt.Printf("ProtectBlob: Can't generate iv\n")
		return nil
	}
      
	serializedKey, err := proto.Marshal(k)
	if err != nil {
		fmt.Printf("ProtectBlob: Can't serialize key\n")
		return nil
	}

	sealedKey := make([]byte, len(serializedKey) + 128)
	sealedKey, err = TEESeal(enclaveType, "test-enclave", serializedKey, len(serializedKey) + 128)
	if err != nil {
		fmt.Printf("ProtectBlob: TEESeal failed\n")
		return nil
	}

	pb.EncryptedKey = sealedKey

	encryptedData := GeneralAuthenticatedEncrypt(k.GetKeyType(), buffer, k.SecretKeyBits, iv)
	if encryptedData == nil {
		fmt.Printf("ProtectBlob: Can't AuthenticatedEncrypt Data\n")
		return nil
	}
	pb.EncryptedData = encryptedData
	serializedBlob, err := proto.Marshal(pb)
	if serializedBlob == nil {
		fmt.Printf("ProtectBlob: Can't serialize ProtectedBlobMessage\n")
		return nil
	}
	return serializedBlob
}

func UnprotectBlob(enclaveType string, k *certprotos.KeyMessage, blob []byte) []byte {
	pb := new(certprotos.ProtectedBlobMessage)
	if pb == nil {
		fmt.Printf("UnprotectBlob: Can't new ProtectedBlobMessage\n")
		return nil
	}
	err := proto.Unmarshal(blob, pb)
	if err != nil {
		fmt.Printf("UnprotectBlob: Can't unmarshal ProtectedBlobMessage\n")
		return nil
	}

	if pb.EncryptedKey == nil {
		fmt.Printf("UnprotectBlob: Encrypted key blob is nil\n")
		return nil
	}
	serializedKey := make([]byte, len(pb.EncryptedKey) + 128)
	serializedKey, err = TEEUnSeal(enclaveType, "test-enclave", pb.EncryptedKey, len(pb.EncryptedKey) + 128)
	if err != nil {
		fmt.Printf("UnprotectBlob: Can't Unseal encrypted key\n")
		return nil
	}
	
	err = proto.Unmarshal(serializedKey, k)
	if err != nil {
		fmt.Printf("UnprotectBlob: Can't unmarshal key\n")
		return nil
	}

	if k.GetKeyType() != "aes-256-cbc-hmac-sha256" {
		fmt.Printf("UnprotectBlob: Wrong key type for authenticated encrypt\n")
		return nil
	}
	buffer := GeneralAuthenticatedDecrypt(k.GetKeyType(), pb.EncryptedData, k.SecretKeyBits)

	return buffer
}

func SavePolicyStore(enclaveType string, ps *certprotos.PolicyStoreMessage, fileName string) bool {
	serializedStore, err := proto.Marshal(ps)
	if err != nil {
		fmt.Printf("SavePolicyStore: Can't serialize store\n")
		return false
	}

	k := ConstructKeyForProtect("protect-key", "aes-256-cbc-hmac-sha256")
	if k == nil {
		fmt.Printf("SavePolicyStore: Can't construct protect key\n")
		return false
	}
	encryptedBlob := ProtectBlob(enclaveType, k, serializedStore)
	if encryptedBlob == nil {
		fmt.Printf("SavePolicyStore: Can't construct protect key\n")
		return false
	}

	if ioutil.WriteFile(fileName, encryptedBlob, 0666) != nil {
		fmt.Printf("SavePolicyStore: Can't write encrypted store\n")
		return false
	}
	return true
}

func RecoverPolicyStore(enclaveType string, fileName string, ps *certprotos.PolicyStoreMessage) bool {

	encryptedStore, err := os.ReadFile(fileName)
	if err != nil {
		fmt.Printf("RecoverPolicyStore: Can't read encrypted store\n")
		return false
	}

	k := new(certprotos.KeyMessage)
	if k == nil {
		fmt.Printf("RecoverPolicyStore: Can't new key message\n")
		return false
	}

	serializedStore := UnprotectBlob(enclaveType, k, encryptedStore)
	if serializedStore == nil {
		fmt.Printf("RecoverPolicyStore: Can't unprotect store\n")
		return false
	}

        // Debug
	// fmt.Printf("RecoverPolicyStore, intermediate key:\n")
	// PrintKey(k)

	err = proto.Unmarshal(serializedStore, ps)
	if err != nil {
		fmt.Printf("RecoverPolicyStore: Can't unmarshal store\n")
		return false
	}
	
	return true
}

func EncapsulateData(ek *certprotos.KeyMessage, alg string, data []byte, edm *certprotos.EncapsulatedDataMessage) bool {
	if ek.KeyType == nil || *edm.EncapsulatingKeyType != "rsa-4096-public" {
		fmt.Printf("EncapsulateData: unsupported encryption algorithm\n")
		return false
	}
	if edm.EncryptionAlgorithm == nil || *edm.EncryptionAlgorithm != "aes-256-gcm" {
		fmt.Printf("EncapsulateData: unsupported encryption algorithm\n")
		return false
	}
	edm.EncapsulatingKeyType = ek.KeyType
	edm.EncryptionAlgorithm = &alg

	encryptKey := make([]byte, 32)
	_, err := rand.Read(encryptKey)
	if err != nil {
		fmt.Printf("EncapsulateData: Can't generate key")
		return false
	}

	iv := make([]byte, 16)
	_, err = rand.Read(iv)
	if err != nil {
		fmt.Printf("EncapsulateData: Can't generate iv")
		return false
	}

	// edm.EncapsulatedKey =

	out := GeneralAuthenticatedEncrypt(alg, data, encryptKey, iv)
	if out == nil {
		fmt.Printf("EncapsulateData: decryption failed\n")
		return false
	}
	edm.EncryptedData = out
	return true
}

func DecapsulateData(ek *certprotos.KeyMessage, edm *certprotos.EncapsulatedDataMessage) []byte {
	if edm.EncapsulatingKeyType == nil || *edm.EncapsulatingKeyType != "rsa-4096-private" {
		fmt.Printf("DecapsulateData: unsupported decryption algorithm\n")
		return nil
	}
	if edm.EncryptionAlgorithm == nil || *edm.EncryptionAlgorithm != "aes-256-gcm" {
		fmt.Printf("DecapsulateData: unsupported decryption algorithm\n")
		return nil
	}

	decryptedKey := make([]byte, 32)
	return GeneralAuthenticatedDecrypt(*edm.EncryptionAlgorithm, edm.EncryptedData, decryptedKey)
}

func ConstructPlatformEvidencePackage(attestingEnclaveType string, purpose string, evList *certprotos.EvidenceList, serializedAttestation []byte) *certprotos.EvidencePackage {
	return nil
}

//  --------------------------------------------------------------------

