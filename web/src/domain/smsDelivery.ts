// The one place that decides how an outgoing SMS's delivery state is presented.
//
// This distinction is the whole point of the module, and it is a correctness
// requirement rather than a styling preference:
//
//   SMS-SUBMIT -> submit_report_success   the SMSC ACCEPTED the message
//                                          -> NOT proof the handset received it
//   SMS-STATUS-REPORT with TP-ST = 0x00   the handset RECEIVED it
//
// The project has already been bitten by conflating the two: the UI showed a
// message as sent, the recipient never got it, and the carrier's own records had
// no matching charge. So `accepted` must never look like `delivered`, and a
// missing status report must never be silently upgraded to either.
//
// Previously these four cases were four inline v-if branches in Sms.vue with the
// meaning carried only by a `title` attribute, which screen readers surface
// inconsistently or not at all.

/** Wire values of `message.status` for an outgoing (type 2) message. */
export const SMS_STATUS_ACCEPTED = 2
export const SMS_STATUS_FAILED = 3
export const SMS_STATUS_AWAITING_REPORT = 4
export const SMS_STATUS_DELIVERED = 5

export type SmsDeliveryPresentation = {
  /** Closed enum, for tests and conditional logic. */
  kind: 'delivered' | 'accepted' | 'awaiting' | 'failed' | 'none'
  /** The glyph shown next to the timestamp. */
  glyph: string
  /** Tailwind text colour class. */
  toneClass: string
  /**
   * Full sentence, used as BOTH the tooltip and the accessible name. It spells out
   * the accepted/delivered distinction in words, because the glyph alone cannot:
   * a check and an arrow look equally "done" at 12px to anyone not briefed on the
   * convention.
   */
  description: string
}

const NONE: SmsDeliveryPresentation = {
  kind: 'none',
  glyph: '',
  toneClass: '',
  description: '',
}

/**
 * @param type 1 = incoming, 2 = outgoing. Only outgoing messages carry delivery state.
 */
export function smsDeliveryPresentation(
  type: number | null | undefined,
  status: number | null | undefined
): SmsDeliveryPresentation {
  if (type !== 2) return NONE

  switch (status) {
    case SMS_STATUS_DELIVERED:
      // The only state that may claim the handset got it.
      return {
        kind: 'delivered',
        glyph: '✓',
        toneClass: 'text-success-600 dark:text-success-400',
        description: '状态报告已确认收件终端收到',
      }
    case SMS_STATUS_ACCEPTED:
      // Deliberately NOT the accent colour. Accepted is a waypoint, not a success,
      // and the accent is reserved for things the operator can act on.
      return {
        kind: 'accepted',
        glyph: '↑',
        toneClass: 'text-sky-600 dark:text-sky-400',
        description: '短信中心已确认提交，不代表收件人已收到',
      }
    case SMS_STATUS_AWAITING_REPORT:
      return {
        kind: 'awaiting',
        glyph: '…',
        toneClass: 'text-warning-600 dark:text-warning-400',
        description: '已提交，等待运营商回执',
      }
    case SMS_STATUS_FAILED:
      return {
        kind: 'failed',
        glyph: '✗',
        toneClass: 'text-danger-600 dark:text-danger-400',
        description: '发送失败',
      }
    default:
      return NONE
  }
}
