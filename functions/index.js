"use strict";

const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");

if (!admin.apps.length) {
  admin.initializeApp();
}

setGlobalOptions({
  region: "europe-west1",
  maxInstances: 20
});

const db = admin.firestore();

const ROLE_RANK = {
  user: 0,
  moderator: 1,
  admin: 2,
  superadmin: 3
};

const VALID_ROLES = new Set(Object.keys(ROLE_RANK));
const VALID_POINT_TYPES = new Set([
  "safe",
  "block",
  "danger2",
  "trash",
  "question",
  "poop"
]);
const VALID_SANCTION_TYPES = new Set(["mute", "ban"]);

function requireAuth(req) {
  if (!req.auth) {
    throw new HttpsError("unauthenticated", "Потрібна авторизація");
  }
  return req.auth;
}

function getRole(req) {
  return req.auth?.token?.role || "user";
}

function hasMinRole(currentRole, minRole) {
  return (ROLE_RANK[currentRole] ?? 0) >= (ROLE_RANK[minRole] ?? 0);
}

function ensureMinRole(req, minRole) {
  const auth = requireAuth(req);
  const role = getRole(req);
  if (!hasMinRole(role, minRole)) {
    throw new HttpsError("permission-denied", "Недостатньо прав");
  }
  return { auth, role };
}

function cleanString(value, maxLen = 200) {
  const text = String(value ?? "").trim();
  return text.slice(0, maxLen);
}

function toDurationHours(raw, fallbackHours) {
  const num = Number(raw);
  if (!Number.isFinite(num)) return fallbackHours;
  return Math.max(1, Math.min(num, 24 * 30));
}

function sanctionDocId({ uid, clientId }) {
  if (uid) return `uid_${uid}`;
  if (clientId) return `client_${clientId}`;
  throw new HttpsError("invalid-argument", "Потрібен uid або clientId");
}

async function writeAudit(action, req, payload = {}) {
  await db.collection("audit_log").add({
    action,
    actorUid: req.auth?.uid || null,
    actorRole: getRole(req),
    payload,
    createdAt: admin.firestore.FieldValue.serverTimestamp()
  });
}

exports.setUserRole = onCall(async req => {
  const { auth } = ensureMinRole(req, "superadmin");
  const uid = cleanString(req.data?.uid, 128);
  const role = cleanString(req.data?.role, 30);

  if (!uid) {
    throw new HttpsError("invalid-argument", "uid обов'язковий");
  }

  if (!VALID_ROLES.has(role)) {
    throw new HttpsError("invalid-argument", "Некоректна роль");
  }

  const userRecord = await admin.auth().getUser(uid);
  const claims = userRecord.customClaims || {};

  await admin.auth().setCustomUserClaims(uid, {
    ...claims,
    role
  });

  await db.doc(`users/${uid}`).set(
    {
      role,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedBy: auth.uid
    },
    { merge: true }
  );

  await writeAudit("set_user_role", req, { uid, role });
  return { ok: true, uid, role };
});

exports.setEmergencyMode = onCall(async req => {
  const { auth, role } = ensureMinRole(req, "admin");
  const enabled = !!req.data?.enabled;
  const reason = cleanString(req.data?.reason, 200);

  await db.doc("app_config/global").set(
    {
      emergencyMode: enabled,
      emergencyReason: reason || null,
      emergencyUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
      emergencyUpdatedBy: auth.uid,
      emergencyUpdatedByRole: role
    },
    { merge: true }
  );

  await writeAudit("set_emergency_mode", req, { enabled, reason });
  return { ok: true, emergencyMode: enabled };
});

exports.moderatePoint = onCall(async req => {
  const pointId = cleanString(req.data?.pointId, 128);
  const action = cleanString(req.data?.action, 30);
  const reason = cleanString(req.data?.reason, 200);
  const patch = req.data?.patch && typeof req.data.patch === "object" ? req.data.patch : {};

  if (!pointId) {
    throw new HttpsError("invalid-argument", "pointId обов'язковий");
  }

  if (!["hide", "unhide", "edit", "delete"].includes(action)) {
    throw new HttpsError("invalid-argument", "Невідома дія");
  }

  if (action === "hide" || action === "unhide") {
    ensureMinRole(req, "moderator");
  } else {
    ensureMinRole(req, "admin");
  }

  const pointRef = db.doc(`points/${pointId}`);
  const pointSnap = await pointRef.get();

  if (!pointSnap.exists) {
    throw new HttpsError("not-found", "Мітку не знайдено");
  }

  const before = pointSnap.data() || {};
  const role = getRole(req);

  if (action === "delete") {
    await pointRef.delete();
    await writeAudit("moderate_point_delete", req, { pointId, reason });
    return { ok: true, pointId, action };
  }

  const update = {
    moderatedAt: admin.firestore.FieldValue.serverTimestamp(),
    moderatedByUid: req.auth.uid,
    moderatedByRole: role
  };

  if (action === "hide" || action === "unhide") {
    const hidden = action === "hide";
    update.hidden = hidden;
    update.moderation = {
      status: hidden ? "hidden" : "visible",
      reason: reason || null,
      at: Date.now(),
      byUid: req.auth.uid,
      byRole: role
    };
  }

  if (action === "edit") {
    if (patch.desc !== undefined) {
      const nextDesc = cleanString(patch.desc, 100);
      if (!nextDesc) {
        throw new HttpsError("invalid-argument", "Опис не може бути порожнім");
      }
      update.desc = nextDesc;
    }

    if (patch.type !== undefined) {
      const nextType = cleanString(patch.type, 30);
      if (!VALID_POINT_TYPES.has(nextType)) {
        throw new HttpsError("invalid-argument", "Некоректний тип мітки");
      }
      update.type = nextType;
      update.typeChangedNotice = nextType !== before.type;
    }

    if (patch.status !== undefined) {
      update.status = cleanString(patch.status, 80);
    }

    update.editedAt = admin.firestore.FieldValue.serverTimestamp();
    update.editedByUid = req.auth.uid;
    update.editedByRole = role;
  }

  await pointRef.update(update);
  await writeAudit("moderate_point", req, { pointId, action, reason, patch });
  return { ok: true, pointId, action };
});

exports.massHideByCity = onCall(async req => {
  ensureMinRole(req, "admin");

  const city = cleanString(req.data?.city, 80);
  const type = cleanString(req.data?.type, 30);
  const reason = cleanString(req.data?.reason, 200);
  const hidden = req.data?.hidden !== false;

  if (!city) {
    throw new HttpsError("invalid-argument", "city обов'язкове");
  }

  if (type && !VALID_POINT_TYPES.has(type)) {
    throw new HttpsError("invalid-argument", "Некоректний type");
  }

  let pointsQuery = db.collection("points").where("city", "==", city);
  if (type) {
    pointsQuery = pointsQuery.where("type", "==", type);
  }

  const snap = await pointsQuery.get();
  if (snap.empty) {
    return { ok: true, affected: 0, city, type: type || null, hidden };
  }

  let affected = 0;
  let batch = db.batch();
  let ops = 0;

  for (const docSnap of snap.docs) {
    batch.update(docSnap.ref, {
      hidden,
      moderatedAt: admin.firestore.FieldValue.serverTimestamp(),
      moderatedByUid: req.auth.uid,
      moderatedByRole: getRole(req),
      moderation: {
        status: hidden ? "hidden" : "visible",
        reason: reason || null,
        at: Date.now(),
        byUid: req.auth.uid,
        byRole: getRole(req),
        scope: "mass_city"
      }
    });

    affected += 1;
    ops += 1;

    if (ops >= 400) {
      await batch.commit();
      batch = db.batch();
      ops = 0;
    }
  }

  if (ops > 0) {
    await batch.commit();
  }

  await writeAudit("mass_hide_by_city", req, {
    city,
    type: type || null,
    hidden,
    affected,
    reason
  });

  return { ok: true, affected, city, type: type || null, hidden };
});

exports.setSanction = onCall(async req => {
  const { auth, role } = ensureMinRole(req, "admin");

  const uid = cleanString(req.data?.uid, 128);
  const clientId = cleanString(req.data?.clientId, 128);
  const sanctionType = cleanString(req.data?.sanctionType || "mute", 20);
  const reason = cleanString(req.data?.reason, 240);

  if (!uid && !clientId) {
    throw new HttpsError("invalid-argument", "Потрібен uid або clientId");
  }

  if (!VALID_SANCTION_TYPES.has(sanctionType)) {
    throw new HttpsError("invalid-argument", "Некоректний тип санкції");
  }

  if (sanctionType === "ban" && !hasMinRole(role, "admin")) {
    throw new HttpsError("permission-denied", "Для ban потрібні права admin");
  }

  const fallbackHours = sanctionType === "ban" ? 168 : 24;
  const durationHours = toDurationHours(req.data?.durationHours, fallbackHours);
  const expiresAt = admin.firestore.Timestamp.fromMillis(
    Date.now() + durationHours * 60 * 60 * 1000
  );

  const id = sanctionDocId({ uid, clientId });
  await db.doc(`sanctions/${id}`).set(
    {
      uid: uid || null,
      clientId: clientId || null,
      sanctionType,
      reason: reason || null,
      active: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      createdByUid: auth.uid,
      createdByRole: role,
      expiresAt
    },
    { merge: true }
  );

  if (uid) {
    await db.doc(`users/${uid}`).set(
      {
        sanction: {
          sanctionType,
          reason: reason || null,
          expiresAt
        },
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );
  }

  await writeAudit("set_sanction", req, {
    uid: uid || null,
    clientId: clientId || null,
    sanctionType,
    durationHours,
    reason
  });

  return {
    ok: true,
    id,
    sanctionType,
    durationHours,
    expiresAtMillis: expiresAt.toMillis()
  };
});

exports.clearSanction = onCall(async req => {
  ensureMinRole(req, "admin");

  const uid = cleanString(req.data?.uid, 128);
  const clientId = cleanString(req.data?.clientId, 128);
  const id = sanctionDocId({ uid, clientId });

  await db.doc(`sanctions/${id}`).delete();

  if (uid) {
    await db.doc(`users/${uid}`).set(
      {
        sanction: admin.firestore.FieldValue.delete(),
        updatedAt: admin.firestore.FieldValue.serverTimestamp()
      },
      { merge: true }
    );
  }

  await writeAudit("clear_sanction", req, {
    uid: uid || null,
    clientId: clientId || null
  });

  return { ok: true, id };
});

exports.getMySanction = onCall(async req => {
  const auth = requireAuth(req);
  const snap = await db.doc(`sanctions/uid_${auth.uid}`).get();

  if (!snap.exists) {
    return { active: false };
  }

  const data = snap.data() || {};
  const expiresAt = data.expiresAt;
  const active =
    data.active === true &&
    expiresAt instanceof admin.firestore.Timestamp &&
    expiresAt.toMillis() > Date.now();

  return {
    active,
    sanctionType: data.sanctionType || null,
    reason: data.reason || null,
    expiresAtMillis: expiresAt instanceof admin.firestore.Timestamp ? expiresAt.toMillis() : null
  };
});
