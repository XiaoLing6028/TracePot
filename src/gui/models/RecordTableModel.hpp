#pragma once

#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QStringList>
#include <QVariant>
#include <QVector>

namespace tracepot::gui {

// Read-only table of report records. Each row carries display values, optional sort keys (so
// numeric columns sort numerically) and an HTML evidence description for the details panel.
class RecordTableModel : public QAbstractTableModel {
    Q_OBJECT

public:
    static constexpr int SortRole = Qt::UserRole + 1;
    static constexpr int DetailsRole = Qt::UserRole + 2;

    struct Row {
        QVector<QVariant> values;
        QVector<QVariant> sortKeys;  // optional; same length as values when present
        QString details;             // HTML
    };

    explicit RecordTableModel(QStringList headers, QObject* parent = nullptr);

    void setRows(QVector<Row> rows);
    [[nodiscard]] const Row& rowAt(int row) const { return rows_.at(row); }

    [[nodiscard]] int rowCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] int columnCount(const QModelIndex& parent = {}) const override;
    [[nodiscard]] QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    [[nodiscard]] QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

private:
    QStringList headers_;
    QVector<Row> rows_;
};

// Case-insensitive text filter across all columns plus an optional exact-match filter on one column.
class RecordFilterProxy : public QSortFilterProxyModel {
    Q_OBJECT

public:
    explicit RecordFilterProxy(QObject* parent = nullptr);

    void setText(const QString& text);
    void setColumnValue(int column, const QString& value);  // empty value disables the column filter
    void setExcludedValue(int column, const QString& value);

protected:
    [[nodiscard]] bool filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const override;

private:
    QString text_;
    int column_ = -1;
    QString columnValue_;
    int excludedColumn_ = -1;
    QString excludedValue_;
};

}  // namespace tracepot::gui
