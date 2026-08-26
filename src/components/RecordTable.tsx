import { parseRecordView } from '../core/dns/records';
import type { DnsRecord } from '../core/dns/types';
import { bytesBase64, escapeTechnicalText } from '../core/technical-text';

interface RecordTableProps {
  readonly compact?: boolean;
  readonly label?: string;
  readonly records: readonly DnsRecord[];
}

export function RecordTable({
  compact = false,
  label = 'DNS resource records',
  records,
}: RecordTableProps) {
  if (records.length === 0) return <p className="empty-note">No records in this section.</p>;

  return (
    <div aria-label={`${label} table`} className="table-scroll" role="region" tabIndex={0}>
      <table className="record-table">
        <caption className="visually-hidden">{label}</caption>
        <thead>
          <tr>
            <th scope="col">Owner</th>
            <th scope="col">TTL</th>
            <th scope="col">Type</th>
            <th scope="col">Record data</th>
          </tr>
        </thead>
        <tbody>
          {records.map((record, index) => {
            const view = parseRecordView(record);
            return (
              <tr key={`${record.section}-${record.owner}-${record.type}-${String(index)}`}>
                <td className="record-data">
                  <bdi className="technical-value" dir="ltr">
                    {escapeTechnicalText(record.owner)}
                  </bdi>
                </td>
                <td>{record.ttl}</td>
                <td>{record.type}</td>
                <td>
                  <code className="record-value technical-value" dir="ltr">
                    {view.text}
                  </code>
                  {view.fields.length > 1 ? (
                    compact ? (
                      <details className="record-fields-details">
                        <summary>Parsed fields</summary>
                        <dl className="record-fields">
                          {view.fields.map((item) => (
                            <div key={item.label}>
                              <dt>{item.label}</dt>
                              <dd>
                                <bdi className="technical-value" dir="ltr">
                                  {item.value}
                                </bdi>
                              </dd>
                            </div>
                          ))}
                        </dl>
                      </details>
                    ) : (
                      <dl className="record-fields">
                        {view.fields.map((item) => (
                          <div key={item.label}>
                            <dt>{item.label}</dt>
                            <dd>
                              <bdi className="technical-value" dir="ltr">
                                {item.value}
                              </bdi>
                            </dd>
                          </div>
                        ))}
                      </dl>
                    )
                  ) : null}
                  {record.rawRdata.length === 0 ? null : (
                    <details className="raw-evidence-details">
                      <summary>Raw RDATA · {record.rawRdata.length} octets</summary>
                      <code className="record-value technical-value" dir="ltr">
                        Base64: {bytesBase64(record.rawRdata)}
                      </code>
                    </details>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
