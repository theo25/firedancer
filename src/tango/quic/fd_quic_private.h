#ifndef HEADER_fd_src_tango_quic_fd_quic_private_h
#define HEADER_fd_src_tango_quic_fd_quic_private_h

#include "fd_quic.h"
#include "templ/fd_quic_transport_params.h"
#include "fd_quic_conn_map.h"
#include "fd_quic_stream.h"
#include "fd_quic_pkt_meta.h"
#include "crypto/fd_quic_crypto_suites.h"
#include "tls/fd_quic_tls.h"

/* FD_QUIC_DISABLE_CRYPTO: set to 1 to disable packet protection and
   encryption.  Only intended for testing.
   FIXME not fully implemented (#256) */
#ifndef FD_QUIC_DISABLE_CRYPTO
#define FD_QUIC_DISABLE_CRYPTO 0
#endif

enum {
  FD_QUIC_TYPE_INGRESS = 1 << 0,
  FD_QUIC_TYPE_EGRESS  = 1 << 1,

  FD_QUIC_TRANSPORT_PARAMS_RAW_SZ = 1200,
};

#define FD_QUIC_PKT_NUM_UNUSED  (~0ul)
#define FD_QUIC_PKT_NUM_PENDING (~1ul)

/* FD_QUIC_MAGIC is used to signal the layout of shared memory region
   of an fd_quic_t. */

#define FD_QUIC_MAGIC (0xdadf8cfa01cc5460UL)

/* events for time based processing */
struct fd_quic_event {
  ulong            timeout;

  fd_quic_conn_t * conn; /* connection or NULL */
  /* possibly "type", etc., for other kinds of service */
};
typedef struct fd_quic_event fd_quic_event_t;

/* fd_quic_state_t is the internal state of an fd_quic_t.  Valid for
   lifetime of join. */

struct __attribute__((aligned(16UL))) fd_quic_state_private {
  /* Pointer to OpenSSL TLS state (part of quic memory region) */

  fd_quic_tls_t * tls;
  int             keylog_fd;

  /* transport_params: Template for QUIC-TLS transport params extension.
     Contains a mix of mutable and immutable fields.  Immutable fields
     are set on join.  Mutable fields may be modified during packet
     processing.  Any code using this struct must ensure that the
     mutable fields are cleared before using (otherwise would leak a
     side channel).

     Mutable fields include:
     - original_destination_connection_id
     - initial_source_conn_id */

  fd_quic_transport_params_t transport_params;

  /* Various internal state */

  fd_quic_conn_t *       conns;          /* free list of unused connections */
  fd_quic_conn_map_t *   conn_map;       /* map connection ids -> connection */
  fd_quic_event_t *      service_queue;  /* priority queue of connections by service time */

  /* crypto members */
  fd_quic_crypto_ctx_t   crypto_ctx[1];  /* crypto context */

  fd_quic_pkt_meta_t *   pkt_meta;       /* records the metadata for the contents
                                            of each sent packet */

  /* flow control - configured initial limits */
  ulong initial_max_data;           /* directly from transport params */
  ulong initial_max_stream_data[4]; /* from 4 transport params indexed by stream type */

  /* next_ephem_udp_port: Next ephemeral UDP port to allocate */
  ushort next_ephem_udp_port;

  /* last arp/routing tables update */
  ulong ip_table_upd;
};

/* FD_QUIC_STATE_OFF is the offset of fd_quic_state_t within fd_quic_t. */
#define FD_QUIC_STATE_OFF (fd_ulong_align_up( sizeof(fd_quic_t), alignof(fd_quic_state_t) ))

FD_PROTOTYPES_BEGIN

/* fd_quic_get_state returns a pointer to private state area given a
   pointer to fd_quic_t.  Const func, guaranteed to not access memory. */

FD_FN_CONST static inline fd_quic_state_t *
fd_quic_get_state( fd_quic_t * quic ) {
  return (fd_quic_state_t *)( (ulong)quic + FD_QUIC_STATE_OFF );
}

FD_FN_CONST static inline fd_quic_state_t const *
fd_quic_get_state_const( fd_quic_t const * quic ) {
  return (fd_quic_state_t const *)( (ulong)quic + FD_QUIC_STATE_OFF );
}

/* fd_quic_conn_service is called periodically to perform pending
   operations and time based operations.

   args
     quic        managing quic
     conn        connection to service
     now         the current time in ns */
void
fd_quic_conn_service( fd_quic_t *      quic,
                      fd_quic_conn_t * conn,
                      ulong            now );

/* get the service interval, while ensuring the value
   is sufficient */
ulong
fd_quic_get_service_interval( fd_quic_t * quic );


/* reschedule a connection */
void
fd_quic_reschedule_conn( fd_quic_conn_t * conn,
                         ulong            timeout );

/* Memory management **************************************************/

fd_quic_conn_t *
fd_quic_conn_create( fd_quic_t *               quic,
                     fd_quic_conn_id_t const * our_conn_id,
                     fd_quic_conn_id_t const * peer_conn_id,
                     uint                      dst_ip_addr,
                     ushort                    dst_udp_port,
                     int                       server,
                     uint                      version );

/* fd_quic_conn_free frees up resources related to the connection and
   returns it to the connection free list. */
void
fd_quic_conn_free( fd_quic_t *      quic,
                   fd_quic_conn_t * conn );

void
fd_quic_stream_free( fd_quic_t *        quic,
                     fd_quic_conn_t *   conn,
                     fd_quic_stream_t * stream,
                     int                code );

/* Callbacks provided by fd_quic **************************************/

/* used by quic to receive data from network */
int
fd_quic_aio_cb_receive( void *                    context,
                        fd_aio_pkt_info_t const * batch,
                        ulong                     batch_sz,
                        ulong *                   opt_batch_idx,
                        int                       flush );

/* declare callbacks from quic-tls into quic */
int
fd_quic_tls_cb_client_hello( fd_quic_tls_hs_t * hs,
                             void *             context );

int
fd_quic_tls_cb_handshake_data( fd_quic_tls_hs_t *    hs,
                               void *                context,
                               OSSL_ENCRYPTION_LEVEL enc_level,
                               uchar const *         data,
                               ulong                 data_sz );

void
fd_quic_tls_cb_alert( fd_quic_tls_hs_t * hs,
                      void *             context,
                      int                alert );

void
fd_quic_tls_cb_secret( fd_quic_tls_hs_t *           hs,
                       void *                       context,
                       fd_quic_tls_secret_t const * secret );
void
fd_quic_tls_cb_keylog( fd_quic_tls_hs_t * hs,
                       char const *       line );

void
fd_quic_tls_cb_handshake_complete( fd_quic_tls_hs_t * hs,
                                   void *             context  );

int
fd_quic_tls_cb_alpn_select( SSL * ssl,
                            uchar const ** out,
                            uchar       *  outlen,
                            uchar const *  in,
                            uint           inlen,
                            void *         arg );

/* Helpers for calling callbacks **************************************/

static inline ulong
fd_quic_now( fd_quic_t * quic ) {
  return quic->cb.now( quic->cb.now_ctx );
}

static inline void
fd_quic_cb_conn_new( fd_quic_t *      quic,
                     fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_new || conn->called_conn_new ) ) {
    return;
  }

  quic->cb.conn_new( conn, quic->cb.quic_ctx );
  conn->called_conn_new = 1;
}

static inline void
fd_quic_cb_conn_hs_complete( fd_quic_t *      quic,
                             fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_hs_complete ) ) return;
  quic->cb.conn_hs_complete( conn, quic->cb.quic_ctx );
}

static inline void
fd_quic_cb_conn_final( fd_quic_t *      quic,
                       fd_quic_conn_t * conn ) {
  if( FD_UNLIKELY( !quic->cb.conn_final || !conn->called_conn_new ) ) return;
  quic->cb.conn_final( conn, quic->cb.quic_ctx );
}

static inline void
fd_quic_cb_stream_new( fd_quic_t *        quic,
                       fd_quic_stream_t * stream,
                       int                stream_type ) {
  if( FD_UNLIKELY( !quic->cb.stream_new ) ) return;
  quic->cb.stream_new( stream, quic->cb.quic_ctx, stream_type );

  /* update metrics */
  ulong stream_id = stream->stream_id;
  quic->metrics.stream_opened_cnt[ stream_id&0x3 ]++;
  quic->metrics.stream_active_cnt[ stream_id&0x3 ]++;
}

static inline void
fd_quic_cb_stream_receive( fd_quic_t *        quic,
                           fd_quic_stream_t * stream,
                           void *             stream_ctx,
                           uchar const *      data,
                           ulong              data_sz,
                           ulong              offset,
                           int                fin ) {
  if( FD_UNLIKELY( !quic->cb.stream_receive ) ) return;
  quic->cb.stream_receive( stream, stream_ctx, data, data_sz, offset, fin );

  /* update metrics */
  quic->metrics.stream_rx_event_cnt++;
  quic->metrics.stream_rx_byte_cnt += data_sz;
}

static inline void
fd_quic_cb_stream_notify( fd_quic_t *        quic,
                          fd_quic_stream_t * stream,
                          void *             stream_ctx,
                          int                event ) {
  if( FD_UNLIKELY( !quic->cb.stream_notify ) ) return;
  quic->cb.stream_notify( stream, stream_ctx, event );

  /* update metrics */
  ulong stream_id = stream->stream_id;
  quic->metrics.stream_closed_cnt[ stream_id&0x3 ]++;
  quic->metrics.stream_active_cnt[ stream_id&0x3 ]--;
}


void
fd_quic_pkt_meta_retry( fd_quic_t *          quic,
                        fd_quic_conn_t *     conn,
                        int                  force );

/* reclaim resources associated with packet metadata
   this is called in response to received acks */
void
fd_quic_reclaim_pkt_meta( fd_quic_conn_t *     conn,
                          fd_quic_pkt_meta_t * pkt_meta,
                          uint                 enc_level );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_tango_quic_fd_quic_private_h */
