#include "gui/models/RecordTableModel.hpp"

namespace tracepot::gui {

RecordTableModel::RecordTableModel(QStringList headers, QObject* parent)
    : QAbstractTableModel(parent), headers_(std::move(headers))
{
}

void RecordTableModel::setRows(QVector<Row> rows)
{
    beginResetModel();
    rows_ = std::move(rows);
    endResetModel();
}

int RecordTableModel::rowCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

int RecordTableModel::columnCount(const QModelIndex& parent) const
{
    return parent.isValid() ? 0 : static_cast<int>(headers_.size());
}

QVariant RecordTableModel::data(const QModelIndex& index, int role) const
{
    if (!index.isValid() || index.row() >= rows_.size() || index.column() >= headers_.size()) {
        return {};
    }
    const Row& row = rows_.at(index.row());
    const QVariant value = index.column() < row.values.size() ? row.values.at(index.column()) : QVariant();
    switch (role) {
    case Qt::DisplayRole:
        return value;
    case Qt::ToolTipRole:
        return value.toString().size() > 60 ? value : QVariant();
    case SortRole:
        if (index.column() < row.sortKeys.size() && row.sortKeys.at(index.column()).isValid()) {
            return row.sortKeys.at(index.column());
        }
        return value;
    case DetailsRole:
        return row.details;
    default:
        return {};
    }
}

QVariant RecordTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal && role == Qt::DisplayRole && section < headers_.size()) {
        return headers_.at(section);
    }
    return QAbstractTableModel::headerData(section, orientation, role);
}

RecordFilterProxy::RecordFilterProxy(QObject* parent) : QSortFilterProxyModel(parent)
{
    setSortRole(RecordTableModel::SortRole);
    setSortCaseSensitivity(Qt::CaseInsensitive);
}

void RecordFilterProxy::setText(const QString& text)
{
    text_ = text.trimmed();
    invalidateFilter();
}

void RecordFilterProxy::setColumnValue(int column, const QString& value)
{
    column_ = value.isEmpty() ? -1 : column;
    columnValue_ = value;
    invalidateFilter();
}

void RecordFilterProxy::setExcludedValue(int column, const QString& value)
{
    excludedColumn_ = value.isEmpty() ? -1 : column;
    excludedValue_ = value;
    invalidateFilter();
}

bool RecordFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex& sourceParent) const
{
    const auto* model = sourceModel();
    if (model == nullptr) {
        return false;
    }
    if (column_ >= 0 &&
        model->index(sourceRow, column_, sourceParent).data().toString().compare(columnValue_, Qt::CaseInsensitive) != 0) {
        return false;
    }
    if (excludedColumn_ >= 0 && model->index(sourceRow, excludedColumn_, sourceParent)
                                        .data()
                                        .toString()
                                        .compare(excludedValue_, Qt::CaseInsensitive) == 0) {
        return false;
    }
    if (text_.isEmpty()) {
        return true;
    }
    for (int column = 0; column < model->columnCount(sourceParent); ++column) {
        if (model->index(sourceRow, column, sourceParent).data().toString().contains(text_, Qt::CaseInsensitive)) {
            return true;
        }
    }
    return false;
}

}  // namespace tracepot::gui
