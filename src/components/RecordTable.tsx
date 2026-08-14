import { parseRecordView } from '../core/dns/records';
import type { DnsRecord } from '../core/dns/types';

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
                <td className="record-data">{record.owner}</td>
                <td>{record.ttl}</td>
                <td>{record.type}</td>
                <td>
                  <code className="record-value">{view.text}</code>
                  {view.fields.length > 1 ? (
                    compact ? (
                      <details className="record-fields-details">
                        <summary>Parsed fields</summary>
                        <dl className="record-fields">
                          {view.fields.map((item) => (
                            <div key={item.label}>
                              <dt>{item.label}</dt>
                              <dd>{item.value}</dd>
                            </div>
                          ))}
                        </dl>
                      </details>
                    ) : (
                      <dl className="record-fields">
                        {view.fields.map((item) => (
                          <div key={item.label}>
                            <dt>{item.label}</dt>
                            <dd>{item.value}</dd>
                          </div>
                        ))}
                      </dl>
                    )
                  ) : null}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
