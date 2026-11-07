# ethers-attest

Pacote ao lado do ethers. Não altera o `Signer` e não assina transação Ethereum.

O recibo AFiR v1 conferido por `verify_afir_receipt` tem corpo de 174 bytes e assinatura ML-DSA-65 de 3.309 bytes. O bloco assinado tem 3.483 bytes. O corpo começa com `version` `0x01` e `profile` `0x01`, e segue com `policy_id` (16), `model_fp` (32), `chunk_cid` (36), `input_hash` (32), `output_hash` (32), `session_nonce` (16) e `timestamp` (8, big-endian).

`encodePayload` e `decodePayload` escrevem e leem esse corpo. Um corpo decodificado não é um recibo verificado. `verifyAfirReceipt` entrega os 3.483 bytes e a chave pública do host à função `verify_afir_receipt` de `arkhe-verify-wasm`. Este pacote não executa ML-DSA-65 e não emite recibo.

`open_cid` não está neste pacote. A string `bafkr4i…` é decodificada pela aplicação antes dos 36 bytes irem para `kernel/arkhe-net`.

A transação que a EVM aceita continua assinada com `secp256k1` pelo ethers. `ROOT_ENTERS_MMR` neste protocolo é a constante `false`.

```js
import { verifyAfirReceipt } from "ethers-attest";

const json = await verifyAfirReceipt(wasm.verify_afir_receipt, signed, hostPublicKey, expectationJson);
```
