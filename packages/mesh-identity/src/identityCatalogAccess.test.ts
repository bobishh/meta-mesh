import { describe, expect, it } from "vitest"
import { certificateHash, createRecoverableIdentity, publicKeyId, signEnvelope, type LocalProfile } from "./index"
import { createDelegatedCertificate } from "./deviceAuthorization"
import { createIdentityEnrollmentDevice } from "./identityEnrollment"
import {
  openIdentityCatalogAccessForApplication,
  openIdentityCatalogAccessForManager,
  sealIdentityCatalogAccessForApplication,
  sealIdentityCatalogAccessForManager,
  type IdentityCatalogAccessManagerBinding,
  type IdentityCatalogAccessApplicationBinding,
} from "./identityCatalogAccess"

describe("Identity catalog access sealing", () => {
  it("Given a signed catalog binding, when a pinned manager opens its sealed bytes, then preserve exact opaque payload", async () => {
    const owner = (await createRecoverableIdentity("better", "Catalog owner")).profile
    const manager = await createManagerDevice(owner, "Identity manager")
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const binding: IdentityCatalogAccessManagerBinding = {
      serviceId: await publicKeyId(service.identity.publicKey),
      personId: owner.identity.personId,
      applicationOrigin: "https://boards.example",
      catalogId: "private-identity-catalog",
      sourceRevision: 4,
      recipientDeviceId: manager.device.deviceId,
      recipientPublicKeyId: await publicKeyId(manager.device.publicKey),
    }
    const access = new TextEncoder().encode('{"scopeId":"opaque-scope","readToken":"opaque-token"}')

    const ciphertext = await sealIdentityCatalogAccessForManager(access, binding, manager.device.publicKey)
    await expect(openIdentityCatalogAccessForManager(ciphertext, manager, binding)).resolves.toEqual(access)
  })

  it("Given a sealed catalog access envelope, when any recipient or authority binding changes, then reject it", async () => {
    const owner = (await createRecoverableIdentity("better", "Catalog owner")).profile
    const manager = await createManagerDevice(owner, "Identity manager")
    const otherManager = await createManagerDevice(owner, "Other manager")
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const binding: IdentityCatalogAccessManagerBinding = {
      serviceId: await publicKeyId(service.identity.publicKey),
      personId: owner.identity.personId,
      applicationOrigin: "https://boards.example",
      catalogId: "private-identity-catalog",
      sourceRevision: 4,
      recipientDeviceId: manager.device.deviceId,
      recipientPublicKeyId: manager.device.deviceId,
    }
    const ciphertext = await sealIdentityCatalogAccessForManager(new TextEncoder().encode("opaque"), binding,
      manager.device.publicKey)

    await expect(openIdentityCatalogAccessForManager(ciphertext, otherManager, binding)).rejects.toThrow()
    await expect(openIdentityCatalogAccessForManager(ciphertext, manager, {
      ...binding,
      applicationOrigin: "https://foreign.example",
    })).rejects.toThrow()
    await expect(openIdentityCatalogAccessForManager(ciphertext, manager, {
      ...binding,
      catalogId: "another-catalog",
    })).rejects.toThrow()
    await expect(openIdentityCatalogAccessForManager(ciphertext, manager, {
      ...binding,
      sourceRevision: 5,
    })).rejects.toThrow()
  })

  it("Given a sealed catalog access envelope, when its ciphertext is altered, then reject it", async () => {
    const owner = (await createRecoverableIdentity("better", "Catalog owner")).profile
    const manager = await createManagerDevice(owner, "Identity manager")
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const binding: IdentityCatalogAccessManagerBinding = {
      serviceId: await publicKeyId(service.identity.publicKey),
      personId: owner.identity.personId,
      applicationOrigin: "https://boards.example",
      catalogId: "private-identity-catalog",
      sourceRevision: 1,
      recipientDeviceId: manager.device.deviceId,
      recipientPublicKeyId: manager.device.deviceId,
    }
    const ciphertext = await sealIdentityCatalogAccessForManager(new TextEncoder().encode("opaque"), binding,
      manager.device.publicKey)
    const altered = `${ciphertext.slice(0, -1)}${ciphertext.endsWith("A") ? "B" : "A"}`

    await expect(openIdentityCatalogAccessForManager(altered, manager, binding)).rejects.toThrow()
  })

  it("Given manager-sealed catalog access, when Identity rebinds it to one app request, then only that app key and challenge can open it", async () => {
    const owner = (await createRecoverableIdentity("better", "Catalog owner")).profile
    const manager = await createManagerDevice(owner, "Identity manager")
    const app = await createDataDevice(owner, "Board app")
    const service = (await createRecoverableIdentity("better", "Rusty service")).profile
    const managerBinding: IdentityCatalogAccessManagerBinding = {
      serviceId: await publicKeyId(service.identity.publicKey),
      personId: owner.identity.personId,
      applicationOrigin: "https://boards.example",
      catalogId: "private-identity-catalog",
      sourceRevision: 4,
      recipientDeviceId: manager.device.deviceId,
      recipientPublicKeyId: manager.device.deviceId,
    }
    const access = new TextEncoder().encode('{"scopeId":"opaque-scope"}')
    const managerCiphertext = await sealIdentityCatalogAccessForManager(access, managerBinding, manager.device.publicKey)
    const opened = await openIdentityCatalogAccessForManager(managerCiphertext, manager, managerBinding)
    const appBinding: IdentityCatalogAccessApplicationBinding = {
      ...managerBinding,
      recipientDeviceId: app.device.deviceId,
      recipientPublicKeyId: app.device.deviceId,
      challenge: "a".repeat(64),
      expiresAt: Date.now() + 60_000,
    }
    const appCiphertext = await sealIdentityCatalogAccessForApplication(opened, appBinding, app.device.publicKey)

    await expect(openIdentityCatalogAccessForApplication(appCiphertext, app, appBinding)).resolves.toEqual(access)
    await expect(openIdentityCatalogAccessForApplication(appCiphertext, app, {
      ...appBinding,
      challenge: "b".repeat(64),
    })).rejects.toThrow()
    await expect(openIdentityCatalogAccessForApplication(appCiphertext, app, {
      ...appBinding,
      expiresAt: appBinding.expiresAt + 1,
    })).rejects.toThrow()
  })
})

async function createManagerDevice(owner: LocalProfile, displayName: string): Promise<LocalProfile> {
  const enrolled = await createIdentityEnrollmentDevice(displayName)
  const certificate = await createDelegatedCertificate(owner.privateKeys.devicePrivateKey, owner.device.deviceId,
    owner.identity.personId, enrolled.device.deviceId, enrolled.device.publicKey, await certificateHash(owner.certificate))
  return {
    identity: owner.identity,
    device: enrolled.device,
    certificate,
    privateKeys: { devicePrivateKey: enrolled.privateKey },
  }
}

async function createDataDevice(owner: LocalProfile, displayName: string): Promise<LocalProfile> {
  const enrolled = await createIdentityEnrollmentDevice(displayName)
  const certificate = await signEnvelope(owner.privateKeys.devicePrivateKey, {
    kind: "device-certificate" as const,
    version: 1 as const,
    personId: owner.identity.personId,
    deviceId: enrolled.device.deviceId,
    devicePublicKey: enrolled.device.publicKey,
    issuerCertificateHash: await certificateHash(owner.certificate),
    canEnrollDevices: false,
  }, owner.device.deviceId)
  return {
    identity: owner.identity,
    device: enrolled.device,
    certificate,
    privateKeys: { devicePrivateKey: enrolled.privateKey },
  }
}
