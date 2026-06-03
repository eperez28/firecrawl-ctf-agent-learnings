#include <stdint.h>
#include <string.h>

typedef struct AuthAuditView {
  int exists;
  int source;
  int stored_mask;
  int effective_mask;
  int revoked;
  int requires_key;
  int key_attached;
  int not_yet_valid;
  int expired;
  int disabled_by_ancestor;
  int usable;
} AuthAuditView;

enum {
  LOCAL_PROFILE = 1,
  IDENTITY_BUNDLE = 2,
  LOCAL_ONLY = 1,
  BUNDLE_ONLY = 2,
  AUTO = 3,
  ERR_OK = 0,
  ERR_DUPLICATE_ID = 1,
  ERR_UNKNOWN_GRANT = 2,
  ERR_WRONG_SOURCE = 3,
  ERR_NON_DELEGATABLE = 4,
  ERR_PERMISSION_WIDENING = 5,
  ERR_CHILD_START_BEFORE_PARENT = 6,
  ERR_CHILD_EXPIRY_AFTER_PARENT = 7,
  ERR_NULL_OUTPUT = 8,
  ERR_REVOKED_PARENT = 9,
  ERR_CAPACITY = 10
};

#define MAX_GRANTS 1048576
#define ID_HASH_SIZE 2097152
#define SUBJECT_HASH_SIZE 524288
#define RESOURCE_HASH_SIZE 1048576

typedef struct Grant {
  int id;
  int subject;
  int resource;
  int source;
  int perms;
  int64_t not_before;
  int64_t expires;
  int delegatable;
  int requires_key;
  int key_attached;
  int revoked;
  int parent;
  int inherited_mask;
  int ancestor_block_count;
  int next_id;
  int next_subject;
  int next_resource;
  int first_child;
  int next_sibling;
} Grant;

typedef struct SubjectNode {
  int subject;
  int source;
  int head;
  int bundle_count;
  int next;
} SubjectNode;

typedef struct ResourceNode {
  int subject;
  int source;
  int resource;
  int head;
  int next;
} ResourceNode;

static Grant grants[MAX_GRANTS];
static int grant_count;
static int id_heads[ID_HASH_SIZE];
static SubjectNode subjects[MAX_GRANTS * 2];
static int subject_count;
static int subject_heads[SUBJECT_HASH_SIZE];
static ResourceNode resources[MAX_GRANTS];
static int resource_count;
static int resource_heads[RESOURCE_HASH_SIZE];
static int last_error;

static unsigned hash_int(int value, unsigned mod) {
  uint32_t x = (uint32_t)value;
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x % mod;
}

static void set_error(int code) { last_error = code; }

static int find_grant_index(int grant_id) {
  int bucket = (int)hash_int(grant_id, ID_HASH_SIZE);
  for (int i = id_heads[bucket]; i != -1; i = grants[i].next_id) {
    if (grants[i].id == grant_id) return i;
  }
  return -1;
}

static int get_subject_node(int subject, int source, int create) {
  int bucket = (int)hash_int(subject * 31 + source, SUBJECT_HASH_SIZE);
  for (int i = subject_heads[bucket]; i != -1; i = subjects[i].next) {
    if (subjects[i].subject == subject && subjects[i].source == source) return i;
  }
  if (!create || subject_count >= MAX_GRANTS * 2) return -1;
  int idx = subject_count++;
  subjects[idx].subject = subject;
  subjects[idx].source = source;
  subjects[idx].head = -1;
  subjects[idx].bundle_count = 0;
  subjects[idx].next = subject_heads[bucket];
  subject_heads[bucket] = idx;
  return idx;
}

static int get_resource_node(int subject, int source, int resource, int create) {
  int bucket = (int)hash_int(subject * 131 + source * 17 + resource, RESOURCE_HASH_SIZE);
  for (int i = resource_heads[bucket]; i != -1; i = resources[i].next) {
    if (resources[i].subject == subject && resources[i].source == source &&
        resources[i].resource == resource) {
      return i;
    }
  }
  if (!create || resource_count >= MAX_GRANTS) return -1;
  int idx = resource_count++;
  resources[idx].subject = subject;
  resources[idx].source = source;
  resources[idx].resource = resource;
  resources[idx].head = -1;
  resources[idx].next = resource_heads[bucket];
  resource_heads[bucket] = idx;
  return idx;
}

static int subject_has_bundle(int subject) {
  int node = get_subject_node(subject, IDENTITY_BUNDLE, 0);
  return node >= 0 && subjects[node].bundle_count > 0;
}

static int add_grant(int grant_id, int subject_id, int resource_id,
                     int perms_mask, int64_t not_before_ts,
                     int64_t expires_ts, int delegatable, int requires_key,
                     int source, int parent) {
  if (find_grant_index(grant_id) >= 0) {
    set_error(ERR_DUPLICATE_ID);
    return 0;
  }
  if (grant_count >= MAX_GRANTS) {
    set_error(ERR_CAPACITY);
    return 0;
  }
  int idx = grant_count++;
  grants[idx].id = grant_id;
  grants[idx].subject = subject_id;
  grants[idx].resource = resource_id;
  grants[idx].source = source;
  grants[idx].perms = perms_mask;
  grants[idx].not_before = not_before_ts;
  grants[idx].expires = expires_ts;
  grants[idx].delegatable = delegatable ? 1 : 0;
  grants[idx].requires_key = (source == IDENTITY_BUNDLE && requires_key) ? 1 : 0;
  grants[idx].key_attached = grants[idx].requires_key ? 0 : 1;
  grants[idx].revoked = 0;
  grants[idx].parent = parent;
  grants[idx].inherited_mask = perms_mask & (parent >= 0 ? grants[parent].inherited_mask : perms_mask);
  grants[idx].ancestor_block_count = parent >= 0
                                         ? grants[parent].ancestor_block_count +
                                               (grants[parent].revoked ||
                                                (grants[parent].source == IDENTITY_BUNDLE &&
                                                 grants[parent].requires_key &&
                                                 !grants[parent].key_attached))
                                         : 0;
  grants[idx].first_child = -1;
  grants[idx].next_sibling = parent >= 0 ? grants[parent].first_child : -1;
  if (parent >= 0) grants[parent].first_child = idx;

  int id_bucket = (int)hash_int(grant_id, ID_HASH_SIZE);
  grants[idx].next_id = id_heads[id_bucket];
  id_heads[id_bucket] = idx;

  int subject_node = get_subject_node(subject_id, source, 1);
  if (subject_node >= 0) {
    grants[idx].next_subject = subjects[subject_node].head;
    subjects[subject_node].head = idx;
    if (source == IDENTITY_BUNDLE) subjects[subject_node].bundle_count++;
  } else {
    grants[idx].next_subject = -1;
  }
  int resource_node = get_resource_node(subject_id, source, resource_id, 1);
  if (resource_node >= 0) {
    grants[idx].next_resource = resources[resource_node].head;
    resources[resource_node].head = idx;
  } else {
    grants[idx].next_resource = -1;
  }
  set_error(ERR_OK);
  return 1;
}

static int directly_unusable(const Grant *g, int64_t ts) {
  return g->revoked || ts < g->not_before || ts >= g->expires ||
         (g->source == IDENTITY_BUNDLE && g->requires_key && !g->key_attached);
}

static void add_descendant_block_delta(int idx, int delta) {
  for (int child = grants[idx].first_child; child != -1; child = grants[child].next_sibling) {
    grants[child].ancestor_block_count += delta;
    add_descendant_block_delta(child, delta);
  }
}

static int effective_mask_for_index(int idx, int64_t ts, int *ancestor_disabled) {
  if (idx < 0) return 0;
  Grant *g = &grants[idx];
  if (ancestor_disabled) *ancestor_disabled = g->ancestor_block_count > 0;
  if (g->ancestor_block_count > 0 || directly_unusable(g, ts)) return 0;
  return g->inherited_mask;
}

__attribute__((visibility("default"))) void auth_reset(void) {
  grant_count = 0;
  subject_count = 0;
  resource_count = 0;
  last_error = ERR_OK;
  for (int i = 0; i < ID_HASH_SIZE; i++) id_heads[i] = -1;
  for (int i = 0; i < SUBJECT_HASH_SIZE; i++) subject_heads[i] = -1;
  for (int i = 0; i < RESOURCE_HASH_SIZE; i++) resource_heads[i] = -1;
}

__attribute__((visibility("default"))) int
auth_create_local_grant(int grant_id, int subject_id, int resource_id,
                        int perms_mask, int64_t not_before_ts,
                        int64_t expires_ts, int delegatable) {
  return add_grant(grant_id, subject_id, resource_id, perms_mask, not_before_ts,
                   expires_ts, delegatable, 0, LOCAL_PROFILE, -1);
}

__attribute__((visibility("default"))) int
auth_import_bundle_grant(int grant_id, int subject_id, int resource_id,
                         int perms_mask, int64_t not_before_ts,
                         int64_t expires_ts, int delegatable,
                         int requires_key) {
  return add_grant(grant_id, subject_id, resource_id, perms_mask, not_before_ts,
                   expires_ts, delegatable, requires_key, IDENTITY_BUNDLE, -1);
}

__attribute__((visibility("default"))) int
auth_attach_bundle_key(int grant_id) {
  int idx = find_grant_index(grant_id);
  if (idx < 0) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  if (grants[idx].source != IDENTITY_BUNDLE) {
    set_error(ERR_WRONG_SOURCE);
    return 0;
  }
  int was_blocking = grants[idx].requires_key && !grants[idx].key_attached;
  grants[idx].key_attached = 1;
  if (was_blocking) add_descendant_block_delta(idx, -1);
  set_error(ERR_OK);
  return 1;
}

__attribute__((visibility("default"))) int
auth_delegate(int parent_grant_id, int child_grant_id, int subject_id,
              int resource_id, int perms_mask, int64_t not_before_ts,
              int64_t expires_ts, int delegatable, int requires_key) {
  int parent_idx = find_grant_index(parent_grant_id);
  if (parent_idx < 0) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  if (find_grant_index(child_grant_id) >= 0) {
    set_error(ERR_DUPLICATE_ID);
    return 0;
  }
  Grant *parent = &grants[parent_idx];
  if (parent->revoked) {
    set_error(ERR_REVOKED_PARENT);
    return 0;
  }
  if (!parent->delegatable) {
    set_error(ERR_NON_DELEGATABLE);
    return 0;
  }
  if ((perms_mask & ~parent->perms) != 0) {
    set_error(ERR_PERMISSION_WIDENING);
    return 0;
  }
  if (not_before_ts < parent->not_before) {
    set_error(ERR_CHILD_START_BEFORE_PARENT);
    return 0;
  }
  if (expires_ts > parent->expires) {
    set_error(ERR_CHILD_EXPIRY_AFTER_PARENT);
    return 0;
  }
  return add_grant(child_grant_id, subject_id, resource_id, perms_mask,
                   not_before_ts, expires_ts, delegatable, requires_key,
                   parent->source, parent_idx);
}

__attribute__((visibility("default"))) int auth_revoke(int grant_id) {
  int idx = find_grant_index(grant_id);
  if (idx < 0) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  if (!grants[idx].revoked) {
    grants[idx].revoked = 1;
    add_descendant_block_delta(idx, 1);
  }
  set_error(ERR_OK);
  return 1;
}

__attribute__((visibility("default"))) int auth_check(int subject_id,
                                                      int resource_id,
                                                      int perm_bit, int64_t ts,
                                                      int resolve_mode) {
  int source = resolve_mode;
  if (resolve_mode == AUTO) source = subject_has_bundle(subject_id) ? IDENTITY_BUNDLE : LOCAL_PROFILE;
  if (source != LOCAL_PROFILE && source != IDENTITY_BUNDLE) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  int node = get_resource_node(subject_id, source, resource_id, 0);
  if (node < 0) {
    set_error(ERR_OK);
    return 0;
  }
  for (int i = resources[node].head; i != -1; i = grants[i].next_resource) {
    if (effective_mask_for_index(i, ts, 0) & perm_bit) {
      set_error(ERR_OK);
      return 1;
    }
  }
  set_error(ERR_OK);
  return 0;
}

__attribute__((visibility("default"))) int auth_effective_mask(int grant_id,
                                                               int64_t ts) {
  int idx = find_grant_index(grant_id);
  if (idx < 0) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  set_error(ERR_OK);
  return effective_mask_for_index(idx, ts, 0);
}

__attribute__((visibility("default"))) int
auth_audit_get(int grant_id, int64_t ts, AuthAuditView *out_view) {
  if (!out_view) {
    set_error(ERR_NULL_OUTPUT);
    return 0;
  }
  int idx = find_grant_index(grant_id);
  if (idx < 0) {
    memset(out_view, 0, sizeof(*out_view));
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  Grant *g = &grants[idx];
  int ancestor_disabled = 0;
  int effective = effective_mask_for_index(idx, ts, &ancestor_disabled);
  for (int parent = g->parent; parent != -1; parent = grants[parent].parent) {
    if (directly_unusable(&grants[parent], ts)) {
      ancestor_disabled = 1;
      break;
    }
  }
  out_view->exists = 1;
  out_view->source = g->source;
  out_view->stored_mask = g->perms;
  out_view->effective_mask = effective;
  out_view->revoked = g->revoked;
  out_view->requires_key = g->requires_key;
  out_view->key_attached = g->requires_key ? g->key_attached : 1;
  out_view->not_yet_valid = ts < g->not_before;
  out_view->expired = ts >= g->expires;
  out_view->disabled_by_ancestor = ancestor_disabled;
  out_view->usable = !directly_unusable(g, ts) && !ancestor_disabled;
  set_error(ERR_OK);
  return 1;
}

__attribute__((visibility("default"))) int
auth_count_usable(int subject_id, int64_t ts, int resolve_mode) {
  int source = resolve_mode;
  if (resolve_mode == AUTO) source = subject_has_bundle(subject_id) ? IDENTITY_BUNDLE : LOCAL_PROFILE;
  if (source != LOCAL_PROFILE && source != IDENTITY_BUNDLE) {
    set_error(ERR_UNKNOWN_GRANT);
    return 0;
  }
  int node = get_subject_node(subject_id, source, 0);
  if (node < 0) {
    set_error(ERR_OK);
    return 0;
  }
  int count = 0;
  for (int i = subjects[node].head; i != -1; i = grants[i].next_subject) {
    if (effective_mask_for_index(i, ts, 0) != 0) count++;
  }
  set_error(ERR_OK);
  return count;
}

__attribute__((visibility("default"))) int auth_last_error(void) {
  return last_error;
}
