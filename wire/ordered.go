package wire

import "google.golang.org/protobuf/encoding/protowire"

// Ordered (account-sequence) transaction encoding — the classic cosmos-sdk
// model the TypeScript SDK's performActionSync uses: replay protection is the
// signer's account sequence, not an unordered timeout. This is the counterpart
// to TxBody/AuthInfo (which build UNORDERED transactions). Use these when the
// desktop wants byte-for-byte parity with the SDK's game-action path.

// TxBodyOrdered is cosmos.tx.v1beta1.TxBody with one message and no unordered
// flag or timeout — a plain ordered transaction.
func TxBodyOrdered(msgAny []byte) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, msgAny)
	return b
}

// AuthInfoSeq is cosmos.tx.v1beta1.AuthInfo for one SIGN_MODE_DIRECT signer at
// the given account sequence, an empty fee and the given gas limit.
func AuthInfoSeq(compressedPubKey []byte, gasLimit, sequence uint64) []byte {
	key := bytesField(nil, 1, compressedPubKey)
	pub := any(typeSecpPubKey, key)

	single := varintField(nil, 1, signModeDirect)
	modeInfo := bytesField(nil, 1, single)

	var signer []byte
	signer = bytesField(signer, 1, pub)
	signer = bytesField(signer, 2, modeInfo)
	signer = varintField(signer, 3, sequence) // sequence (omitted only when 0)

	fee := varintField(nil, 2, gasLimit)

	var b []byte
	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendBytes(b, signer)
	b = bytesField(b, 2, fee)
	return b
}

// DecodeAccountNumberAndSequence reads QueryAccountInfoResponse{info{account_number, sequence}}:
// account_number is field 3, sequence is field 4 of BaseAccount.
func DecodeAccountNumberAndSequence(b []byte) (accountNumber, sequence uint64, err error) {
	info, err := firstBytes(b, 1)
	if err != nil {
		return 0, 0, err
	}
	err = walk(info, func(num protowire.Number, typ protowire.Type, _ []byte, v uint64) {
		if typ != protowire.VarintType {
			return
		}
		switch num {
		case 3:
			accountNumber = v
		case 4:
			sequence = v
		}
	})
	return accountNumber, sequence, err
}
