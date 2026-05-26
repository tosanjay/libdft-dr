/* Branch-prediction hints. Verbatim from libdft64/branch_pred.h (no Pin deps). */
#ifndef __BRANCH_PRED_H__
#define __BRANCH_PRED_H__

#define likely(x)       __builtin_expect((x), 1)
#define unlikely(x)     __builtin_expect((x), 0)

#endif /* __BRANCH_PRED_H__ */
