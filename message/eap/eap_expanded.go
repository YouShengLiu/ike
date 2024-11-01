package eap

import (
	"encoding/binary"

	"github.com/pkg/errors"
)

// Definition of EAP expanded

// Types for EAP-5G
// Used in IKE EAP expanded for vendor ID
const VendorId3GPP = 10415

// Used in IKE EAP expanded for vendor data
const VendorTypeEAP5G = 3

var _ EapTypeFormat = &EapExpanded{}

type EapExpanded struct {
	VendorID   uint32
	VendorType uint32
	VendorData []byte
}

func (eapExpanded *EapExpanded) Type() EapType { return EapTypeExpanded }

func (eapExpanded *EapExpanded) Marshal() ([]byte, error) {
	eapExpandedData := make([]byte, 8)

	vendorID := eapExpanded.VendorID & 0x00ffffff
	typeAndVendorID := (uint32(EapTypeExpanded)<<24 | vendorID)

	binary.BigEndian.PutUint32(eapExpandedData[0:4], typeAndVendorID)
	binary.BigEndian.PutUint32(eapExpandedData[4:8], eapExpanded.VendorType)

	if len(eapExpanded.VendorData) == 0 {
		return eapExpandedData, nil
	}

	eapExpandedData = append(eapExpandedData, eapExpanded.VendorData...)

	return eapExpandedData, nil
}

func (eapExpanded *EapExpanded) Unmarshal(b []byte) error {
	if len(b) > 0 {
		if len(b) < 8 {
			return errors.New("EapExpanded: No sufficient bytes to decode the EAP expanded type")
		}

		typeAndVendorID := binary.BigEndian.Uint32(b[0:4])
		eapExpanded.VendorID = typeAndVendorID & 0x00ffffff

		eapExpanded.VendorType = binary.BigEndian.Uint32(b[4:8])

		if len(b) > 8 {
			eapExpanded.VendorData = append(eapExpanded.VendorData, b[8:]...)
		}
	}

	return nil
}
