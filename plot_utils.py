import plotly.graph_objs as go

def generate_roc_scatter(names, values, colors, show_legend=False):

    traces = []

    for i in range(len(names)):
        x = values[i][0].tolist()
        y = values[i][1].tolist()

        traces.append(
            go.Scatter(
                x=x,
                y=y,
                line=dict(color=colors[i]),
                mode='lines',
                showlegend=show_legend,
                name=names[i],
            )
        )

    layout = go.Layout(
        template='plotly_white',
        xaxis=dict(
            title='FPR',
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False
        ),
        yaxis=dict(
            title='TPR',
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False
        ),
    )

    return traces, layout

def generate_marker_scatter(names, values, colors, fills, xlabel, ylabel, show_legend=False):

    traces = []

    for i in range(len(names)):
        x = values[i][0].tolist()
        y = values[i][1].tolist()

        traces.append(
            go.Scatter(
                x=x,
                y=y,
                mode='markers',
                name=names[i],
                marker=dict(
                    color=fills[i],
                    size=20,
                    line=dict(
                        color=colors[i],
                        width=2
                    )
                ),
                showlegend=show_legend
            )
        )

    layout = go.Layout(
        template='plotly_white',
        xaxis=dict(
            title=xlabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False
        ),
        yaxis=dict(
            title=ylabel,
            showgrid=True,
            showline=False,
            showticklabels=True,
            ticks='outside',
            zeroline=False
        ),
    )

    return traces, layout