/*
 * Copyright (C) 2020 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package app.cash.certifikit.attestation

import app.cash.certifikit.Adapters
import app.cash.certifikit.DerHeader.Companion.TAG_CLASS_UNIVERSAL
import okio.ByteString

/**
 * ```
 * KeyDescription ::= SEQUENCE {
 *   attestationVersion         INTEGER,
 *   attestationSecurityLevel   SecurityLevel,
 *   keymasterVersion           INTEGER,
 *   keymasterSecurityLevel     SecurityLevel,
 *   attestationChallenge       OCTET_STRING,
 *   uniqueId                   OCTET_STRING,
 *   softwareEnforced           AuthorizationList,
 *   teeEnforced                AuthorizationList,
 * }
 *
 * SecurityLevel ::= ENUMERATED {
 *   Software                   (0),
 *   TrustedEnvironment         (1),
 *   StrongBox                  (2),
 * }
 * ```
 */
data class KeyDescription(
  val attestationVersion: Long,
  val attestationSecurityLevel: Long,
  val keymasterVersion: Long,
  val keymasterSecurityLevel: Long,
  val attestationChallenge: ByteString,
  val uniqueId: ByteString,
  val softwareEnforced: AuthorizationList,
  val teeEnforced: AuthorizationList
)

/**
 * ```
 * VerifiedBootState ::= ENUMERATED {
 *   Verified                   (0),
 *   SelfSigned                 (1),
 *   Unverified                 (2),
 *   Failed                     (3),
 * }
 *
 * RootOfTrust ::= SEQUENCE {
 *   verifiedBootKey            OCTET_STRING,
 *   deviceLocked               BOOLEAN,
 *   verifiedBootState          VerifiedBootState,
 *   verifiedBootHash           OCTET_STRING,
 * }
 * ```
 */
data class RootOfTrust(
  val verifiedBootKey: ByteString,
  val deviceLocked: Boolean,
  val verifiedBootState: Long,
  val verifiedBootHash: ByteString
)

/**
 * ```
 * AuthorizationList ::= SEQUENCE {
 *   purpose                     [1] EXPLICIT SET OF INTEGER OPTIONAL,
 *   algorithm                   [2] EXPLICIT INTEGER OPTIONAL,
 *   keySize                     [3] EXPLICIT INTEGER OPTIONAL.
 *   digest                      [5] EXPLICIT SET OF INTEGER OPTIONAL,
 *   padding                     [6] EXPLICIT SET OF INTEGER OPTIONAL,
 *   ecCurve                     [10] EXPLICIT INTEGER OPTIONAL,
 *   rsaPublicExponent           [200] EXPLICIT INTEGER OPTIONAL,
 *   rollbackResistance          [303] EXPLICIT NULL OPTIONAL,
 *   activeDateTime              [400] EXPLICIT INTEGER OPTIONAL
 *   originationExpireDateTime   [401] EXPLICIT INTEGER OPTIONAL
 *   usageExpireDateTime         [402] EXPLICIT INTEGER OPTIONAL
 *   noAuthRequired              [503] EXPLICIT NULL OPTIONAL,
 *   userAuthType                [504] EXPLICIT INTEGER OPTIONAL,
 *   authTimeout                 [505] EXPLICIT INTEGER OPTIONAL,
 *   allowWhileOnBody            [506] EXPLICIT NULL OPTIONAL,
 *   trustedUserPresenceRequired [507] EXPLICIT NULL OPTIONAL,
 *   trustedConfirmationRequired [508] EXPLICIT NULL OPTIONAL,
 *   unlockedDeviceRequired      [509] EXPLICIT NULL OPTIONAL,
 *   allApplications             [600] EXPLICIT NULL OPTIONAL,
 *   applicationId               [601] EXPLICIT OCTET_STRING OPTIONAL,
 *   creationDateTime            [701] EXPLICIT INTEGER OPTIONAL,
 *   origin                      [702] EXPLICIT INTEGER OPTIONAL,
 *   rollbackResistant           [703] EXPLICIT NULL OPTIONAL,
 *   rootOfTrust                 [704] EXPLICIT RootOfTrust OPTIONAL,
 *   osVersion                   [705] EXPLICIT INTEGER OPTIONAL,
 *   osPatchLevel                [706] EXPLICIT INTEGER OPTIONAL,
 *   attestationApplicationId    [709] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdBrand          [710] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdDevice         [711] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdProduct        [712] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdSerial         [713] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdImei           [714] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdMeid           [715] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdManufacturer   [716] EXPLICIT OCTET_STRING OPTIONAL,
 *   attestationIdModel          [717] EXPLICIT OCTET_STRING OPTIONAL,
 *   vendorPatchLevel            [718] EXPLICIT INTEGER OPTIONAL,
 *   bootPatchLevel              [719] EXPLICIT INTEGER OPTIONAL,
 * }
 * ```
 */
data class AuthorizationList(
  val purpose: List<Long>? = null,
  val algorithm: Long? = null,
  val keySize: Long? = null,
  val digest: List<Long>? = null,
  val padding: List<Long>? = null,
  val ecCurve: Long? = null,
  val rsaPublicExponent: Long? = null,
  val rollbackResistance: Unit? = null,
  val activeDateTime: Long? = null,
  val originationExpireDateTime: Long? = null,
  val usageExpireDateTime: Long? = null,
  val noAuthRequired: Unit? = null,
  val userAuthType: Long? = null,
  val authTimeout: Long? = null,
  val allowWhileOnBody: Unit? = null,
  val trustedUserPresenceRequired: Unit? = null,
  val trustedConfirmationRequired: Unit? = null,
  val unlockedDeviceRequired: Unit? = null,
  val allApplications: Unit? = null,
  val applicationId: ByteString? = null,
  val creationDateTime: Long? = null,
  val origin: Long? = null,
  val rollbackResistant: Unit? = null,
  val rootOfTrust: RootOfTrust? = null,
  val osVersion: Long? = null,
  val osPatchLevel: Long? = null,
  val attestationApplicationId: ByteString? = null,
  val attestationIdBrand: ByteString? = null,
  val attestationIdDevice: ByteString? = null,
  val attestationIdProduct: ByteString? = null,
  val attestationIdSerial: ByteString? = null,
  val attestationIdImei: ByteString? = null,
  val attestationIdMeid: ByteString? = null,
  val attestationIdManufacturer: ByteString? = null,
  val attestationIdModel: ByteString? = null,
  val vendorPatchLevel: Long? = null,
  val bootPatchLevel: Long? = null
)

object AttestationAdapters {
  internal val rootOfTrust = Adapters.sequence(
      "rootOfTrust",
      Adapters.OCTET_STRING,
      Adapters.BOOLEAN,
      Adapters.INTEGER_AS_LONG.withTag(tagClass = TAG_CLASS_UNIVERSAL, tag = 10),
      Adapters.OCTET_STRING,
      decompose = {
        listOf(
            it.verifiedBootKey,
            it.deviceLocked,
            it.verifiedBootState,
            it.verifiedBootHash
        )
      },
      construct = {
        RootOfTrust(
            verifiedBootKey = it[0] as ByteString,
            deviceLocked = it[1] as Boolean,
            verifiedBootState = it[2] as Long,
            verifiedBootHash = it[3] as ByteString
        )
      }
  )

  internal val authorizationList = Adapters.sequence(
      "authorizationList",
      Adapters.INTEGER_AS_LONG.asSetOf()
          .withExplicitBox(tag = 1)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 2)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 3)
          .optional(),
      Adapters.INTEGER_AS_LONG.asSetOf()
          .withExplicitBox(tag = 5)
          .optional(),
      Adapters.INTEGER_AS_LONG.asSetOf()
          .withExplicitBox(tag = 6)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 10)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 200)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 303)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 400)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 401)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 402)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 503)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 504)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 505)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 506)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 507)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 508)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 509)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 600)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 601)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 701)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 702)
          .optional(),
      Adapters.NULL.withExplicitBox(tag = 703)
          .optional(),
      rootOfTrust.withExplicitBox(tag = 704)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 705)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 706)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 709)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 710)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 711)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 712)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 713)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 714)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 715)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 716)
          .optional(),
      Adapters.OCTET_STRING.withExplicitBox(tag = 717)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 718)
          .optional(),
      Adapters.INTEGER_AS_LONG.withExplicitBox(tag = 719)
          .optional(),
      decompose = {
        listOf(
            it.purpose,
            it.algorithm,
            it.keySize,
            it.digest,
            it.padding,
            it.ecCurve,
            it.rsaPublicExponent,
            it.rollbackResistance,
            it.activeDateTime,
            it.originationExpireDateTime,
            it.usageExpireDateTime,
            it.noAuthRequired,
            it.userAuthType,
            it.authTimeout,
            it.allowWhileOnBody,
            it.trustedUserPresenceRequired,
            it.trustedConfirmationRequired,
            it.unlockedDeviceRequired,
            it.allApplications,
            it.applicationId,
            it.creationDateTime,
            it.origin,
            it.rollbackResistant,
            it.rootOfTrust,
            it.osVersion,
            it.osPatchLevel,
            it.attestationApplicationId,
            it.attestationIdBrand,
            it.attestationIdDevice,
            it.attestationIdProduct,
            it.attestationIdSerial,
            it.attestationIdImei,
            it.attestationIdMeid,
            it.attestationIdManufacturer,
            it.attestationIdModel,
            it.vendorPatchLevel,
            it.bootPatchLevel
        )
      },
      construct = {
        AuthorizationList(
            purpose = it[0] as List<Long>?,
            algorithm = it[1] as Long?,
            keySize = it[2] as Long?,
            digest = it[3] as List<Long>?,
            padding = it[4] as List<Long>?,
            ecCurve = it[5] as Long?,
            rsaPublicExponent = it[6] as Long?,
            rollbackResistance = it[7] as Unit?,
            activeDateTime = it[8] as Long?,
            originationExpireDateTime = it[9] as Long?,
            usageExpireDateTime = it[10] as Long?,
            noAuthRequired = it[11] as Unit?,
            userAuthType = it[12] as Long?,
            authTimeout = it[13] as Long?,
            allowWhileOnBody = it[14] as Unit?,
            trustedUserPresenceRequired = it[15] as Unit?,
            trustedConfirmationRequired = it[16] as Unit?,
            unlockedDeviceRequired = it[17] as Unit?,
            allApplications = it[18] as Unit?,
            applicationId = it[19] as ByteString?,
            creationDateTime = it[20] as Long?,
            origin = it[21] as Long?,
            rollbackResistant = it[22] as Unit?,
            rootOfTrust = it[23] as RootOfTrust?,
            osVersion = it[24] as Long?,
            osPatchLevel = it[25] as Long?,
            attestationApplicationId = it[26] as ByteString?,
            attestationIdBrand = it[27] as ByteString?,
            attestationIdDevice = it[28] as ByteString?,
            attestationIdProduct = it[29] as ByteString?,
            attestationIdSerial = it[30] as ByteString?,
            attestationIdImei = it[31] as ByteString?,
            attestationIdMeid = it[32] as ByteString?,
            attestationIdManufacturer = it[33] as ByteString?,
            attestationIdModel = it[34] as ByteString?,
            vendorPatchLevel = it[35] as Long?,
            bootPatchLevel = it[36] as Long?
        )
      }
  )

  internal val keyDescription = Adapters.sequence(
      "KeyDescription",
      Adapters.INTEGER_AS_LONG,
      Adapters.INTEGER_AS_LONG.withTag(tagClass = TAG_CLASS_UNIVERSAL, tag = 10),
      Adapters.INTEGER_AS_LONG,
      Adapters.INTEGER_AS_LONG.withTag(tagClass = TAG_CLASS_UNIVERSAL, tag = 10),
      Adapters.OCTET_STRING,
      Adapters.OCTET_STRING,
      authorizationList,
      authorizationList,
      decompose = {
        listOf(
            it.attestationVersion,
            it.attestationSecurityLevel,
            it.keymasterVersion,
            it.keymasterSecurityLevel,
            it.attestationChallenge,
            it.uniqueId,
            it.softwareEnforced,
            it.teeEnforced
        )
      },
      construct = {
        KeyDescription(
            attestationVersion = it[0] as Long,
            attestationSecurityLevel = it[1] as Long,
            keymasterVersion = it[2] as Long,
            keymasterSecurityLevel = it[3] as Long,
            attestationChallenge = it[4] as ByteString,
            uniqueId = it[5] as ByteString,
            softwareEnforced = it[6] as AuthorizationList,
            teeEnforced = it[7] as AuthorizationList
        )
      }
  )

  const val KEY_DESCRIPTION_OID = "1.3.6.1.4.1.11129.2.1.17"
}
